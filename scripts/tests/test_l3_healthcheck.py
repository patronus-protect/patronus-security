import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / 'ark-api/deploy/l3-triton/healthcheck.py'
spec = importlib.util.spec_from_file_location('l3_healthcheck', MODULE)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class HealthcheckTests(unittest.TestCase):
    def fixture(self):
        return {'model_name': 'test', 'model_version': '1', 'outputs': [
            {'name': name, 'shape': [1, count], 'datatype': 'FP32', 'data': [0.] * count}
            for name, count in monitor.OUTPUTS.items()]}

    def test_requires_real_valid_inference_outputs(self):
        monitor.validate(self.fixture(), 'test')
        for mutate in [lambda x: x.update(model_name='other'),
                       lambda x: x.update(outputs=[]),
                       lambda x: x['outputs'][0].update(data=[float('nan')]),
                       lambda x: x['outputs'][0].update(shape=[2, 1]),
                       lambda x: x['outputs'][1].update(name='injection_logits')]:
            response = copy.deepcopy(self.fixture())
            mutate(response)
            with self.assertRaises(ValueError):
                monitor.validate(response, 'test')

    def test_alarm_after_three_failures_and_recovery_only_after_alert(self):
        state = {}
        for n in range(1, 4):
            state, event = monitor.advance(state, False, 'HTTP 500', str(n))
            self.assertEqual(event, 'DOWN' if n == 3 else None)
        state['alert_sent'] = True
        state, event = monitor.advance(state, False, 'HTTP 500', '4')
        self.assertIsNone(event)
        state, event = monitor.advance(state, True, 'OK', '5')
        self.assertEqual(event, 'RECOVERED')
        self.assertEqual(state['failure_since'], '1')
        state['alert_sent'] = False
        self.assertIsNone(monitor.advance(state, True, 'OK', '6')[1])

    def test_success_resets_consecutive_failure_counter(self):
        state, _ = monitor.advance({}, False, 'timeout', '1')
        state, _ = monitor.advance(state, True, 'OK', '2')
        state, event = monitor.advance(state, False, 'timeout', '3')
        self.assertEqual(state['failures'], 1)
        self.assertEqual(state['failure_since'], '3')
        self.assertIsNone(event)

    def test_failed_mail_is_retried_and_success_is_deduplicated_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'state.json'
            config = {'mail': {'to': 'ops@example.invalid'}}
            with patch.object(monitor, 'probe', side_effect=ValueError('Triton inference HTTP 500')), \
                 patch.object(monitor, 'notify', side_effect=[OSError('mail down'), None]) as send, \
                 patch('builtins.print'):
                for _ in range(5):
                    monitor.run(config, path)
                self.assertEqual(send.call_count, 2)
                self.assertTrue(json.loads(path.read_text())['alert_sent'])
            with patch.object(monitor, 'probe', return_value=12), \
                 patch.object(monitor, 'notify') as send, patch('builtins.print'):
                monitor.run(config, path)
                monitor.run(config, path)
                send.assert_called_once()
                self.assertEqual(send.call_args.args[1], 'RECOVERED')

    def test_missing_mail_is_visible_and_does_not_mark_alarm_delivered(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(monitor, 'probe', side_effect=TimeoutError()), \
             patch.object(monitor, 'notify') as send, patch('builtins.print'):
            path = Path(d) / 'state.json'
            for _ in range(3):
                monitor.run({}, path)
            state = json.loads(path.read_text())
            self.assertFalse(state['mail_configured'])
            self.assertFalse(state.get('alert_sent', False))
            send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
