import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[2] / 'ark-api/deploy/fleet.py'
spec = importlib.util.spec_from_file_location('fleet', PATH)
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)


def identity(n):
    return f'00000000-0000-4000-8000-{n:012d}'


class FleetPlanningTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            'datacenter_id': identity(99), 'minimum_cubes': 1,
            'protected_server_ids': [identity(98)],
            'slots': [{'name': f'cube-{i}', 'server_id': identity(i),
                       'private_ip': f'192.0.2.{i}'} for i in range(1, 4)],
        }
        self.inventory = {
            'datacenter_id': identity(99),
            'servers': [{'id': identity(i), 'name': f'cube-{i}', 'type': 'CUBE',
                         'state': 'RUNNING', 'resource_state': 'AVAILABLE',
                         'nics': [{'lan': 1, 'ips': [f'192.0.2.{i}']}]}
                        for i in range(1, 4)],
        }

    def test_reduction_is_only_a_proposal_and_keeps_unmanaged_servers(self):
        self.inventory['servers'].append({'id': identity(98), 'name': 'shared',
                                         'nics': [{'ips': ['192.0.2.98']}]})
        result = fleet.plan(self.config, self.inventory, 2)
        self.assertTrue(result['read_only'])
        self.assertEqual([a['action'] for a in result['actions']],
                         ['retain', 'retain', 'drain_then_remove'])
        self.assertEqual(result['target_workers'], 6)
        self.assertNotIn(identity(98), [a['server_id'] for a in result['actions']])

    def test_empty_slot_requires_creation_and_verification(self):
        self.config['slots'][2]['server_id'] = None
        self.inventory['servers'].pop()
        self.assertEqual(fleet.plan(self.config, self.inventory, 3)['actions'][2]['action'],
                         'create_and_verify')

    def test_fail_closed_on_identity_or_capacity_changes(self):
        cases = [
            lambda c, i: c['protected_server_ids'].append(identity(3)),
            lambda c, i: i['servers'][2].update(type='ENTERPRISE'),
            lambda c, i: i['servers'][2].update(name='redis'),
            lambda c, i: i['servers'][0].update(state='SHUTOFF'),
            lambda c, i: i['servers'][2].update(resource_state='BUSY'),
            lambda c, i: i['servers'].pop(),
            lambda c, i: i.update(datacenter_id=identity(97)),
            lambda c, i: c['slots'][2].update(server_id=identity(2)),
            lambda c, i: c['slots'][2].update(private_ip='192.0.2.2'),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                c, i = copy.deepcopy(self.config), copy.deepcopy(self.inventory)
                mutate(c, i)
                with self.assertRaises(ValueError):
                    fleet.plan(c, i, 2)
        for target in (0, 4, True):
            with self.assertRaises(ValueError):
                fleet.plan(self.config, self.inventory, target)

    def test_refuses_to_reuse_an_occupied_address(self):
        self.config['slots'][2]['server_id'] = None
        with self.assertRaises(ValueError):
            fleet.plan(self.config, self.inventory, 3)

    def test_inventory_never_exports_volume_user_data_or_credentials(self):
        server = {'id': identity(1), 'properties': {'name': 'cube-1', 'type': 'CUBE'},
                  'entities': {'volumes': {'items': [{'properties': {'userData': 'secret'}}]}}}
        self.assertNotIn('secret', str(fleet.summarize(server)))
        self.assertNotIn('volumes', fleet.summarize(server))

    def test_token_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'token'
            token.write_text('example-token\n')
            token.chmod(0o600)
            self.assertEqual(fleet.read_token(token), 'example-token')
            link = Path(directory) / 'link'
            link.symlink_to(token)
            with self.assertRaises(OSError):
                fleet.read_token(link)
            token.chmod(0o644)
            with self.assertRaises(ValueError):
                fleet.read_token(token)

    def test_bearer_requests_cannot_follow_redirects(self):
        self.assertIsNone(fleet.NoRedirect().redirect_request(
            None, None, 302, '', {}, 'https://example.invalid/'))


if __name__ == '__main__':
    unittest.main()
