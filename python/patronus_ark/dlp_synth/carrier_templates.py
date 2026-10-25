# SPDX-License-Identifier: GPL-3.0-only
"""Carrier families and rule profiles for ``dlp_synth.carriers`` (E04).

A family is one document shape (a .env file, a Kubernetes Secret, a Go file, a German
support ticket ...) that belongs to exactly one split. Templates use these markers:

* ``<<value>>`` once: the generated value, wrapped by the rule profile and escaped by
  the family (``json``, ``xml`` or ``indent``).
* ``<<KEY>>``, ``<<key>>``, ``<<keyCamel>>``, ``<<KeyPascal>>``, ``<<key-kebab>>``,
  ``<<Key-Header>>``: the profile key name in the carrier's naming style.
* ``<<label>>``: the profile label in the family language.

``env_ref`` replaces the first string (which contains ``<<value>>``) by an environment or
template reference for the ``env_ref`` hard negative. Templates hold no secret values;
the self-scan test keeps it that way.
"""

from __future__ import annotations

import textwrap
from typing import NamedTuple


class Family(NamedTuple):
    id: str
    format: str
    language: str
    split: str
    template: str
    env_ref: tuple[str, str]
    escape: tuple[str, ...] = ()
    indent: int = 0
    multiline: bool = False
    accepts: frozenset[str] = frozenset({"secret", "identifier"})
    content: tuple[str, ...] = ()
    syntax: str | None = None
    code_language: str | None = None


class Profile(NamedTuple):
    entity: str
    group: str
    kind: str
    key: str
    label_en: str
    label_de: str
    # "<<value>>" inside a carrier-independent wrapper, or {generator: wrapper}.
    wrap: str | dict[str, str] | None = None


def _t(text: str) -> str:
    return textwrap.dedent(text.removeprefix("\n"))


INFRA = frozenset({"secret"})
CONFIG = frozenset({"secret", "identifier"})
PROSE = frozenset({"secret", "identifier", "fragment"})
CODE = ("content.source_code",)
LOG = ("content.system_log",)


def _code(id, language, split, code_language, template, env_ref, escape=("json",), multiline=True):
    return Family(
        id, "code", language, split, _t(template), env_ref, escape, 0, multiline, CONFIG, CODE, None, code_language
    )


def _prose(id, format, language, split, template, env_ref):
    return Family(id, format, language, split, _t(template), env_ref, (), 0, True, PROSE)


FAMILIES = (
    # ── dev ──────────────────────────────────────────────────────────────────
    Family(
        "env.app_dotenv", "env", "de", "dev",
        _t("""
            # .env – lokale Entwicklung (nicht einchecken)
            APP_ENV=development
            APP_PORT=8080
            LOG_LEVEL=debug
            <<KEY>>=<<value>>
            REDIS_URL=redis://localhost:6379/0
            """),
        ("<<value>>", "${VAULT_<<KEY>>}"),
    ),
    Family(
        "yaml.app_config", "yaml", "en", "dev",
        _t("""
            # config/production.yaml
            server:
              host: 0.0.0.0
              port: 8443
              request_timeout: 30s
            integrations:
              upstream:
                enabled: true
                base_url: https://api.example.com/v2
                <<key>>: "<<value>>"
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "yaml",
    ),
    Family(
        "json.service_config", "json", "en", "dev",
        _t("""
            {
              "service": "invoice-export",
              "region": "eu-central-1",
              "retries": 3,
              "credentials": {
                "<<key>>": "<<value>>"
              },
              "trace_id": "3f2b8c1e-9a4d-4e7b-b1c2-5d6e7f8a9b0c"
            }
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "json",
    ),
    Family(
        "toml.service", "toml", "de", "dev",
        _t("""
            # Konfiguration des Abgleichdienstes
            [server]
            bind = "127.0.0.1:9000"
            worker = 4

            [upstream]
            basis_url = "https://api.example.de/v2"
            <<key>> = "<<value>>"
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "toml",
    ),
    Family(
        "hcl.terraform_provider", "hcl", "en", "dev",
        _t("""
            terraform {
              required_version = ">= 1.6"
            }

            provider "acme" {
              region  = "eu-central-1"
              <<key>> = "<<value>>"
            }

            resource "acme_bucket" "reports" {
              name = "reports-prod"
            }
            """),
        ('"<<value>>"', "var.<<key>>"),
        ("json",), 0, True, INFRA,
    ),
    Family(
        "xml.app_config", "xml", "de", "dev",
        _t("""
            <?xml version="1.0" encoding="utf-8"?>
            <!-- Einstellungen für den Rechnungsexport -->
            <configuration>
              <appSettings>
                <add key="Umgebung" value="Produktion" />
                <add key="<<KeyPascal>>" value="<<value>>" />
              </appSettings>
            </configuration>
            """),
        ('"<<value>>"', '"%<<KEY>>%"'),
        ("xml",), 0, False, CONFIG, (), "xml",
    ),
    Family(
        "properties.spring", "properties", "en", "dev",
        _t("""
            # application.properties
            spring.application.name=order-service
            server.port=8081
            spring.datasource.url=jdbc:postgresql://db:5432/orders
            app.<<key-kebab>>=<<value>>
            management.endpoints.web.exposure.include=health,info
            """),
        ("<<value>>", "${<<KEY>>}"),
        ("json",), 0, True,
    ),
    Family(
        "shell.export_cli", "shell", "de", "dev",
        _t("""
            $ export <<KEY>>='<<value>>'
            $ ./bin/sync --region eu-west-1 --dry-run
            Synchronisiere 214 Objekte … fertig (3,2 s)
            """),
        ("'<<value>>'", '"$(pass show ci/<<key-kebab>>)"'),
        (), 0, True, INFRA,
    ),
    Family(
        "dockerfile.env", "dockerfile", "en", "dev",
        _t("""
            FROM python:3.12-slim
            WORKDIR /app
            COPY requirements.txt .
            RUN pip install --no-cache-dir -r requirements.txt
            ENV <<KEY>>=<<value>>
            COPY . .
            CMD ["gunicorn", "app:create_app()", "--bind", "0.0.0.0:8000"]
            """),
        ("ENV <<KEY>>=<<value>>", "ARG <<KEY>>\nENV <<KEY>>=${<<KEY>>}"),
        (), 0, False, INFRA,
    ),
    Family(
        "ci_yaml.github_actions", "ci_yaml", "de", "dev",
        _t("""
            # Deployment nach Staging bei jedem Push auf main
            name: deploy
            on:
              push:
                branches: [main]
            jobs:
              deploy:
                runs-on: ubuntu-24.04
                env:
                  <<KEY>>: "<<value>>"
                steps:
                  - uses: actions/checkout@v4
                  - run: ./scripts/deploy.sh staging
            """),
        ('"<<value>>"', "${{ secrets.<<KEY>> }}"),
        ("json",), 0, True, INFRA, (), "yaml",
    ),
    Family(
        "jupyter.code_cell", "jupyter", "de", "dev",
        _t(r"""
            {
             "cells": [
              {
               "cell_type": "markdown",
               "metadata": {},
               "source": ["## Datensätze abrufen"]
              },
              {
               "cell_type": "code",
               "execution_count": 1,
               "metadata": {},
               "outputs": [],
               "source": [
                "import requests\n",
                "<<key>> = \"<<value>>\"\n",
                "antwort = requests.get(\"https://api.example.de/v1/datensaetze\", headers={\"X-Api-Key\": <<key>>}, timeout=10)"
               ]
              }
             ],
             "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
             "nbformat": 4,
             "nbformat_minor": 5
            }
            """),
        (r"\"<<value>>\"", r"os.environ[\"<<KEY>>\"]"),
        ("json", "json"), 0, True, CONFIG, CODE, "json",
    ),
    Family(
        "log.app_text", "log", "en", "dev",
        _t("""
            2026-09-14T08:12:03.441Z INFO  [main] c.a.billing.App - Starting billing-api v2.8.1 on ip-10-0-3-17 (pid 4121)
            2026-09-14T08:12:03.902Z DEBUG [main] c.a.billing.Config - effective config: region=eu-central-1 <<key>>=<<value>> retries=3
            2026-09-14T08:12:04.117Z INFO  [main] c.a.billing.App - Started billing-api in 0.68 s
            """),
        ("<<value>>", "${<<KEY>>}"),
        (), 0, False, PROSE, LOG,
    ),
    Family(
        "http.request_headers", "http", "en", "dev",
        _t("""
            POST /v1/exports HTTP/1.1
            Host: api.example.com
            User-Agent: export-worker/1.4.2
            Accept: application/json
            Content-Type: application/json
            <<Key-Header>>: <<value>>

            {"format": "csv", "since": "2026-09-01"}
            """),
        ("<<value>>", "{{<<keyCamel>>}}"),
    ),
    Family(
        "env.worker_dotenv", "env", "en", "dev",
        _t("""
            # .env for the report worker (copied from .env.example)
            WORKER_QUEUE=reports
            WORKER_CONCURRENCY=4
            <<KEY>>=<<value>>
            SENTRY_ENVIRONMENT=staging
            """),
        ("<<value>>", "${<<KEY>>:?missing}"),
    ),
    Family(
        "yaml.versand_de", "yaml", "de", "dev",
        _t("""
            # Einstellungen für den Versanddienst
            dienst:
              name: versand
              port: 8090
            anbindungen:
              spedition:
                basis_url: https://api.example.de/v1
                <<keyCamel>>: "<<value>>"
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "yaml",
    ),
    Family(
        "json.lagerabgleich_de", "json", "de", "dev",
        _t("""
            {
              "dienst": "lagerabgleich",
              "umgebung": "produktion",
              "zugang": {
                "<<keyCamel>>": "<<value>>",
                "anmerkung": "nur für den nächtlichen Lauf"
              }
            }
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "json",
    ),
    Family(
        "toml.reconciler", "toml", "en", "dev",
        _t("""
            # reconciler settings
            [server]
            listen = "0.0.0.0:7000"
            threads = 8

            [auth]
            <<key>> = "<<value>>"
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "toml",
    ),
    Family(
        "hcl.objektspeicher_de", "hcl", "de", "dev",
        _t("""
            # Zugang für den Objektspeicher, wird in Q4 auf Vault umgestellt
            provider "objektspeicher" {
              region  = "eu-central-1"
              <<key>> = "<<value>>"
            }

            resource "objektspeicher_bucket" "berichte" {
              name = "berichte-prod"
            }
            """),
        ('"<<value>>"', "var.<<key>>"),
        ("json",), 0, True, INFRA,
    ),
    Family(
        "xml.exporter_attribute", "xml", "en", "dev",
        _t("""
            <?xml version="1.0" encoding="utf-8"?>
            <!-- connection settings for the report exporter -->
            <exporter>
              <endpoint url="https://reports.example.com/api" timeout="30" />
              <credentials <<keyCamel>>="<<value>>" />
            </exporter>
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("xml",), 0, False, CONFIG, (), "xml",
    ),
    Family(
        "properties.lager_de", "properties", "de", "dev",
        _t("""
            # Anwendungseinstellungen Lagerverwaltung
            spring.application.name=lagerverwaltung
            server.port=8082
            lager.standort=hamburg
            lager.<<key-kebab>>=<<value>>
            """),
        ("<<value>>", "${<<KEY>>}"),
        ("json",), 0, True,
    ),
    Family(
        "shell.curl_header", "shell", "en", "dev",
        _t("""
            $ curl -sS https://api.example.com/v1/status \\
            >   -H "Accept: application/json" \\
            >   -H "<<Key-Header>>: <<value>>"
            {"status":"ok","version":"3.4.0"}
            """),
        ('"<<Key-Header>>: <<value>>"', '"<<Key-Header>>: $<<KEY>>"'),
        (), 0, False, INFRA,
    ),
    Family(
        "dockerfile.runtime_de", "dockerfile", "de", "dev",
        _t("""
            # Laufzeit-Image für den Abgleichdienst
            FROM eclipse-temurin:21-jre
            WORKDIR /opt/abgleich
            COPY target/abgleich.jar app.jar
            ENV <<KEY>>="<<value>>"
            ENTRYPOINT ["java", "-jar", "app.jar"]
            """),
        ('ENV <<KEY>>="<<value>>"', "ARG <<KEY>>\nENV <<KEY>>=${<<KEY>>}"),
        (), 0, False, INFRA,
    ),
    Family(
        "ci_yaml.nightly_export", "ci_yaml", "en", "dev",
        _t("""
            # nightly export job
            name: nightly-export
            on:
              schedule:
                - cron: "0 2 * * *"
            jobs:
              export:
                runs-on: ubuntu-24.04
                steps:
                  - uses: actions/checkout@v4
                  - run: ./scripts/export.sh
                    env:
                      <<KEY>>: "<<value>>"
            """),
        ('"<<value>>"', "${{ secrets.<<KEY>> }}"),
        ("json",), 0, True, INFRA, (), "yaml",
    ),
    Family(
        "jupyter.env_cell", "jupyter", "en", "dev",
        _t(r"""
            {
             "cells": [
              {
               "cell_type": "code",
               "execution_count": 2,
               "metadata": {},
               "outputs": [],
               "source": [
                "import os\n",
                "os.environ[\"<<KEY>>\"] = \"<<value>>\"\n",
                "client = ReportClient.from_env()"
               ]
              }
             ],
             "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
             "nbformat": 4,
             "nbformat_minor": 5
            }
            """),
        (r"\"<<value>>\"", r"os.environ.get(\"VAULT_<<KEY>>\", \"\")"),
        ("json", "json"), 0, True, CONFIG, CODE, "json",
    ),
    Family(
        "log.abgleich_text_de", "log", "de", "dev",
        _t("""
            2026-09-14 08:12:03,441 INFO  [main] Abgleich gestartet (Version 2.8.1, Knoten lager-02)
            2026-09-14 08:12:03,902 DEBUG [main] Konfiguration geladen: mandant=0042 <<key>>=<<value>> wiederholungen=3
            2026-09-14 08:12:04,117 INFO  [main] Abgleich bereit nach 0,68 s
            """),
        ("<<value>>", "${<<KEY>>}"),
        (), 0, False, PROSE, LOG,
    ),
    Family(
        "http.lieferungen_de", "http", "de", "dev",
        _t("""
            GET /v1/lieferungen?status=offen HTTP/1.1
            Host: api.example.de
            Accept: application/json
            Accept-Language: de-DE
            <<Key-Header>>: <<value>>
            """),
        ("<<value>>", "{{<<keyCamel>>}}"),
    ),
    _code(
        "code.python.client_de", "de", "dev", "python",
        '''
        """Abruf offener Rechnungen aus dem Buchhaltungssystem."""
        import requests

        <<KEY>> = "<<value>>"


        def offene_rechnungen(kunden_id: str) -> list[dict]:
            antwort = requests.get(
                f"https://api.example.de/v1/kunden/{kunden_id}/rechnungen",
                headers={"X-Api-Key": <<KEY>>},
                timeout=10,
            )
            antwort.raise_for_status()
            return antwort.json()["daten"]
        ''',
        ('"<<value>>"', 'os.environ["<<KEY>>"]'),
    ),
    _code(
        "code.javascript.express", "en", "dev", "javascript",
        """
        const express = require("express");
        const { Client } = require("./client");

        const app = express();
        const client = new Client({
          baseUrl: "https://api.example.com",
          <<keyCamel>>: "<<value>>",
        });

        app.get("/health", (_req, res) => res.json({ ok: true }));
        app.listen(3000);
        """,
        ('"<<value>>"', "process.env.<<KEY>>"),
    ),
    _code(
        "code.typescript.service", "en", "dev", "typescript",
        """
        import { HttpClient } from "@acme/http";

        export const <<keyCamel>>: string = "<<value>>";

        export async function listProjects(http: HttpClient): Promise<string[]> {
          const res = await http.get<{ items: { name: string }[] }>("/v1/projects", {
            headers: { "X-Api-Key": <<keyCamel>> },
          });
          return res.items.map((p) => p.name);
        }
        """,
        ('"<<value>>"', 'process.env.<<KEY>> ?? ""'),
    ),
    _code(
        "code.go.client", "en", "dev", "go",
        """
        package billing

        import (
        \t"net/http"
        \t"time"
        )

        const <<keyCamel>> = "<<value>>"

        func NewClient() *http.Client {
        \treturn &http.Client{Timeout: 10 * time.Second}
        }
        """,
        ('const <<keyCamel>> = "<<value>>"', 'var <<keyCamel>> = os.Getenv("<<KEY>>")'),
    ),
    _code(
        "code.java.constant_de", "de", "dev", "java",
        """
        package com.acme.zahlungen;

        import java.net.http.HttpClient;
        import java.time.Duration;

        // Zugangsdaten für den Zahlungsdienst, Umstellung auf Vault folgt
        public final class ZahlungsKonfiguration {
            private static final String <<KEY>> = "<<value>>";

            public static HttpClient client() {
                return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            }
        }
        """,
        ('"<<value>>"', 'System.getenv("<<KEY>>")'),
    ),
    _code(
        "code.csharp.const_de", "de", "dev", "csharp",
        """
        using System.Net.Http;

        namespace Acme.Berichte;

        // Client für den Berichtsdienst
        public static class BerichtsClient
        {
            private const string <<KeyPascal>> = "<<value>>";

            public static HttpClient Erzeugen() => new HttpClient { BaseAddress = new Uri("https://berichte.example.de/") };
        }
        """,
        (
            'private const string <<KeyPascal>> = "<<value>>";',
            'private static readonly string <<KeyPascal>> = Environment.GetEnvironmentVariable("<<KEY>>");',
        ),
    ),
    _code(
        "code.rust.const_de", "de", "dev", "rust",
        """
        use std::time::Duration;

        // Zugang zum Import-Endpunkt
        const <<KEY>>: &str = "<<value>>";

        pub fn client() -> reqwest::Client {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP-Client")
        }
        """,
        ('const <<KEY>>: &str = "<<value>>";', 'static <<KEY>>: &str = env!("<<KEY>>");'),
    ),
    _code(
        "code.ruby.uploader", "en", "dev", "ruby",
        """
        require "net/http"

        module Acme
          class Uploader
            API_HOST = "https://uploads.example.com"
            <<KEY>> = "<<value>>"

            def call(path)
              Net::HTTP.get(URI("#{API_HOST}/#{path}"))
            end
          end
        end
        """,
        ('"<<value>>"', 'ENV.fetch("<<KEY>>")'),
    ),
    _prose(
        "chat.en.standup", "chat", "en", "dev",
        """
        [09:41] maria.k: anyone have the <<label>> for the staging box? CI is red 😕
        [09:43] tom.w: here you go: <<value>>
        [09:43] tom.w: please don't paste it anywhere else, I'll rotate it on Friday
        """,
        ("<<value>>", "it's `$<<KEY>>` in the staging env, ask me if it doesn't resolve"),
    ),
    _prose(
        "chat.de.standup", "chat", "de", "dev",
        """
        [08:15] lena.s: Kurze Frage: Wie lautet der Wert für „<<label>>“ in der Testumgebung? 🙏
        [08:17] daniel.r: <<value>>
        [08:17] daniel.r: Aber bitte nur lokal verwenden, wird nächste Woche getauscht.
        """,
        ("<<value>>", "steht als $<<KEY>> in der .env auf dem Jump-Host"),
    ),
    _prose(
        "ticket.en.integration", "ticket", "en", "dev",
        """
        Ticket #48213 — Integration failing after key rotation
        Priority: High | Component: billing-sync | Reporter: ops-oncall

        Steps to reproduce:
        1. Run `billing-sync --once`
        2. Observe 401 from upstream

        Note from reporter: the job still uses the old <<label>>. Current value in the config: <<value>>
        """,
        ("<<value>>", "${<<KEY>>} (resolved from the job environment)"),
    ),
    _prose(
        "ticket.de.schnittstelle", "ticket", "de", "dev",
        """
        Ticket #20931 – Schnittstelle zum Lieferanten liefert 403
        Priorität: hoch · Komponente: edi-gateway · Gemeldet von: Leitstand

        Beschreibung:
        Seit dem Update am 12.09. schlägt der Abruf fehl. Laut Konfiguration hinterlegt (<<label>>): <<value>>
        Bitte prüfen, ob der Wert noch gültig ist.
        """,
        ("<<value>>", "${<<KEY>>} aus der Umgebung des Jobs"),
    ),
    _prose(
        "mail.en.handover", "mail", "en", "dev",
        """
        From: Alex Turner <alex.turner@example.com>
        To: devops@example.com
        Subject: Credentials for the new reporting job
        Date: Mon, 14 Sep 2026 09:12:44 +0200

        Hi team,

        as discussed, here is the <<label>> for the reporting job:

        <<value>>

        It's only needed until the vault integration is live.

        Thanks,
        Alex
        """,
        ("<<value>>", "(stored in the vault as <<key>>; the job reads it from ${<<KEY>>})"),
    ),
    _prose(
        "mail.de.abschluss", "mail", "de", "dev",
        """
        Von: Katrin Müller <k.mueller@example.de>
        An: it-betrieb@example.de
        Betreff: Zugangsdaten Monatsabschluss
        Datum: Mo., 14. Sep. 2026 08:55:10 +0200

        Hallo zusammen,

        anbei wie besprochen die Zugangsdaten für den Abschlusslauf (<<label>>):

        <<value>>

        Bitte nach dem Lauf löschen.

        Viele Grüße
        Katrin
        """,
        ("<<value>>", "(liegt im Vault unter <<key>>, der Lauf liest ${<<KEY>>})"),
    ),
    # ── holdout ──────────────────────────────────────────────────────────────
    Family(
        "env.compose_quoted", "env", "en", "holdout",
        _t("""
            # docker compose environment (staging)
            COMPOSE_PROJECT_NAME=billing
            POSTGRES_HOST=db
            POSTGRES_PORT=5432
            <<KEY>>="<<value>>"
            FEATURE_FLAGS=export,audit
            """),
        ('"<<value>>"', '"${SECRETS_<<KEY>>}"'),
        ("json",), 0, True,
    ),
    Family(
        "yaml.k8s_secret", "yaml", "de", "holdout",
        _t("""
            # Zugangsdaten für den Abrechnungsdienst
            apiVersion: v1
            kind: Secret
            metadata:
              name: abrechnung-zugang
              namespace: payments
              labels:
                app.kubernetes.io/name: abrechnung
            type: Opaque
            stringData:
              <<key-kebab>>: |
                <<value>>
            """),
        ("|\n    <<value>>", '"{{ .Values.secrets.<<keyCamel>> }}"'),
        ("indent",), 4, True, CONFIG, (), "yaml",
    ),
    Family(
        "json.compact_job", "json", "de", "holdout",
        _t("""
            {"name":"monatsabschluss","beschreibung":"Exportjob für Rechnungen","zeitplan":"0 3 1 * *","einstellungen":{"<<keyCamel>>":"<<value>>","probelauf":false}}
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "json",
    ),
    Family(
        "toml.credentials_literal", "toml", "en", "holdout",
        _t("""
            # ~/.config/acme/credentials.toml
            [profile.default]
            region = "eu-west-1"
            output = "json"

            [profile.default.auth]
            <<key>> = '''<<value>>'''
            """),
        ("'''<<value>>'''", '"${<<KEY>>}"'),
        (), 0, True, CONFIG, (), "toml",
    ),
    Family(
        "hcl.nomad_job", "hcl", "de", "holdout",
        _t("""
            job "abrechnung" {
              datacenters = ["fra1"]

              group "api" {
                task "server" {
                  driver = "docker"

                  # Zugangsdaten bis zur Vault-Migration
                  env {
                    <<KEY>> = <<EOT
            <<value>>
            EOT
                  }
                }
              }
            }
            """),
        ("<<EOT\n<<value>>\nEOT", '"${var.<<key>>}"'),
        (), 0, True, INFRA,
    ),
    Family(
        "xml.maven_settings", "xml", "en", "holdout",
        _t("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!-- Maven settings for the build agents -->
            <settings>
              <servers>
                <server>
                  <id>internal-releases</id>
                  <username>ci-deploy</username>
                  <<<keyCamel>>><<value>></<<keyCamel>>>
                </server>
              </servers>
            </settings>
            """),
        ("<<value>>", "${env.<<KEY>>}"),
        ("xml",), 0, True, CONFIG, (), "xml",
    ),
    Family(
        "properties.ini", "properties", "de", "holdout",
        _t("""
            ; Konfiguration Exportdienst
            [allgemein]
            mandant = 0042
            log_level = INFO

            [api]
            endpunkt = https://api.example.de/v1
            <<key>> = <<value>>
            """),
        ("<<value>>", "%(ENV_<<KEY>>)s"),
    ),
    Family(
        "shell.cli_flag", "shell", "en", "holdout",
        _t("""
            #!/usr/bin/env bash
            # deploy script, run from the repository root
            set -euo pipefail
            ./deploy.sh --env prod --<<key-kebab>> "<<value>>" --timeout 120
            """),
        ('"<<value>>"', '"$<<KEY>>"'),
        (), 0, False, INFRA,
    ),
    Family(
        "dockerfile.build_arg", "dockerfile", "de", "holdout",
        _t("""
            # Build-Image für die Rechnungs-API
            FROM node:20-alpine AS build
            WORKDIR /src
            ARG <<KEY>>="<<value>>"
            RUN npm ci && npm run build
            FROM nginx:1.27-alpine
            COPY --from=build /src/dist /usr/share/nginx/html
            """),
        ('ARG <<KEY>>="<<value>>"', "ARG <<KEY>>"),
        (), 0, False, INFRA,
    ),
    Family(
        "ci_yaml.gitlab", "ci_yaml", "en", "holdout",
        _t("""
            # pipeline for staging deployments
            stages: [test, deploy]
            variables:
              <<KEY>>: "<<value>>"
              DEPLOY_ENV: staging
            deploy:
              stage: deploy
              image: alpine:3.20
              script:
                - ./deploy.sh "$DEPLOY_ENV"
            """),
        ('"<<value>>"', '"${VAULT_<<KEY>>}"'),
        ("json",), 0, True, INFRA, (), "yaml",
    ),
    Family(
        "jupyter.stream_output", "jupyter", "en", "holdout",
        _t(r"""
            {
             "cells": [
              {
               "cell_type": "code",
               "execution_count": 3,
               "metadata": {},
               "outputs": [
                {"name": "stdout", "output_type": "stream", "text": ["config loaded\n", "<<key>>=<<value>>\n"]}
               ],
               "source": ["cfg = load_config()\n", "print_config(cfg)"]
              }
             ],
             "metadata": {},
             "nbformat": 4,
             "nbformat_minor": 5
            }
            """),
        ("<<key>>=<<value>>", "<<key>>=${<<KEY>>}"),
        ("json",), 0, True, CONFIG, CODE, "json",
    ),
    Family(
        "log.jsonl", "log", "de", "holdout",
        _t("""
            {"ts":"2026-09-14T10:02:11.006+02:00","level":"warn","msg":"Anmeldung am Upstream fehlgeschlagen, neuer Versuch","versuch":2}
            {"ts":"2026-09-14T10:02:11.214+02:00","level":"debug","msg":"Request-Header","headers":{"<<Key-Header>>":"<<value>>","Accept":"application/json"}}
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, PROSE, LOG, "jsonl",
    ),
    Family(
        "http.rest_client", "http", "de", "holdout",
        _t("""
            ### Bestellungen abrufen (REST Client)
            @baseUrl = https://api.example.de/v2
            GET {{baseUrl}}/bestellungen?limit=50
            Accept: application/json
            <<Key-Header>>: <<value>>
            """),
        ("<<value>>", "{{$processEnv <<KEY>>}}"),
    ),
    Family(
        "env.systemd_de", "env", "de", "holdout",
        _t("""
            # /etc/abgleich/umgebung – vom systemd-Dienst geladen
            DIENST_NAME=abgleich
            DIENST_PORT=9100
            <<KEY>>='<<value>>'
            """),
        ("'<<value>>'", '"$(cat /run/secrets/<<key>>)"'),
    ),
    Family(
        "yaml.compose_override", "yaml", "en", "holdout",
        _t("""
            # docker-compose.override.yml
            services:
              worker:
                image: registry.example.com/worker:1.9
                environment:
                  <<KEY>>: "<<value>>"
                  LOG_LEVEL: info
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "yaml",
    ),
    Family(
        "json.vscode_launch", "json", "en", "holdout",
        _t("""
            {
              "version": "0.2.0",
              "configurations": [
                {
                  "name": "Debug worker",
                  "type": "node",
                  "request": "launch",
                  "program": "${workspaceFolder}/src/worker.js",
                  "env": { "<<KEY>>": "<<value>>" }
                }
              ]
            }
            """),
        ('"<<value>>"', '"${env:<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "json",
    ),
    Family(
        "toml.export_de", "toml", "de", "holdout",
        _t("""
            # Zugangsdaten für den Exportdienst (lokal)
            [export]
            ziel = "sftp://dateien.example.de/eingang"
            intervall_minuten = 15

            [export.zugang]
            <<key>> = "<<value>>"
            """),
        ('"<<value>>"', '"${<<KEY>>}"'),
        ("json",), 0, True, CONFIG, (), "toml",
    ),
    Family(
        "hcl.terraform_variable", "hcl", "en", "holdout",
        _t("""
            variable "<<key>>" {
              description = "Credential for the upstream API"
              type        = string
              sensitive   = true
              default     = "<<value>>"
            }
            """),
        ('default     = "<<value>>"', "# set via TF_VAR_<<key>>"),
        ("json",), 0, True, INFRA,
    ),
    Family(
        "xml.schnittstelle_de", "xml", "de", "holdout",
        _t("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!-- Verbindungsdaten für die Schnittstelle zum Lager -->
            <Schnittstelle>
              <Endpunkt>https://lager.example.de/api</Endpunkt>
              <<<KeyPascal>>><<value>></<<KeyPascal>>>
            </Schnittstelle>
            """),
        ("<<value>>", "${<<KEY>>}"),
        ("xml",), 0, True, CONFIG, (), "xml",
    ),
    Family(
        "properties.gradle", "properties", "en", "holdout",
        _t("""
            # gradle.properties
            org.gradle.jvmargs=-Xmx2g
            org.gradle.parallel=true
            <<keyCamel>>=<<value>>
            """),
        ("<<value>>", "${<<KEY>>}"),
    ),
    Family(
        "shell.cron_de", "shell", "de", "holdout",
        _t("""
            #!/bin/sh
            # Nächtliche Sicherung, per cron um 02:30
            set -eu
            <<KEY>>="<<value>>" ./sicherung.sh --ziel /mnt/sicherung --behalten 14
            """),
        ('"<<value>>"', '"$(cat /run/secrets/<<key>>)"'),
        (), 0, False, INFRA,
    ),
    Family(
        "dockerfile.go_build", "dockerfile", "en", "holdout",
        _t("""
            # syntax=docker/dockerfile:1
            FROM golang:1.23 AS build
            WORKDIR /src
            COPY . .
            RUN <<KEY>>=<<value>> go build -o /out/api ./cmd/api
            FROM gcr.io/distroless/base-debian12
            COPY --from=build /out/api /api
            """),
        ("RUN <<KEY>>=<<value>> go build", "RUN --mount=type=secret,id=<<key-kebab>> go build"),
        (), 0, False, INFRA,
    ),
    Family(
        "ci_yaml.gitlab_de", "ci_yaml", "de", "holdout",
        _t("""
            # Nächtlicher Export der Stammdaten
            stages: [export]
            stammdaten_export:
              stage: export
              image: python:3.12-slim
              variables:
                <<KEY>>: "<<value>>"
              script:
                - python -m export --ziel s3://stammdaten
              rules:
                - if: '$CI_PIPELINE_SOURCE == "schedule"'
            """),
        ('"<<value>>"', '"${CI_SECRET_<<KEY>>}"'),
        ("json",), 0, True, INFRA, (), "yaml",
    ),
    Family(
        "jupyter.ausgabe_de", "jupyter", "de", "holdout",
        _t(r"""
            {
             "cells": [
              {
               "cell_type": "code",
               "execution_count": 7,
               "metadata": {},
               "outputs": [
                {"name": "stdout", "output_type": "stream", "text": ["Verbindung wird aufgebaut …\n", "verwende <<key>>: <<value>>\n"]}
               ],
               "source": ["verbindung = verbinden(einstellungen)"]
              }
             ],
             "metadata": {},
             "nbformat": 4,
             "nbformat_minor": 5
            }
            """),
        ("<<key>>: <<value>>", "<<key>>: ${<<KEY>>}"),
        ("json",), 0, True, CONFIG, CODE, "json",
    ),
    Family(
        "log.syslog", "log", "en", "holdout",
        _t("""
            Sep 14 10:02:11 web-03 api[2211]: WARN upstream auth rejected, retrying (attempt 2)
            Sep 14 10:02:11 web-03 api[2211]: DEBUG outgoing request headers: Accept=application/json <<Key-Header>>=<<value>>
            """),
        ("<<value>>", "${<<KEY>>}"),
        (), 0, False, PROSE, LOG,
    ),
    Family(
        "http.webhook_update", "http", "en", "holdout",
        _t("""
            PUT /api/v3/webhooks/42 HTTP/2
            Host: hooks.example.com
            Content-Type: application/json
            <<Key-Header>>: <<value>>

            {"url": "https://ci.example.com/hook", "active": true}
            """),
        ("<<value>>", "{{$dotenv <<KEY>>}}"),
    ),
    _code(
        "code.python.settings", "en", "holdout", "python",
        """
        # Settings for the staging environment
        from pathlib import Path

        BASE_DIR = Path(__file__).resolve().parent.parent
        DEBUG = False
        ALLOWED_HOSTS = ["staging.example.com"]

        # TODO: move to the secret store before the release
        <<KEY>> = '<<value>>'
        """,
        ("'<<value>>'", 'env("<<KEY>>")'),
    ),
    _code(
        "code.javascript.module_de", "de", "holdout", "javascript",
        """
        // Konfiguration für den Export-Job
        module.exports = {
          zeitzone: "Europe/Berlin",
          batchGroesse: 500,
          <<keyCamel>>: `<<value>>`,
        };
        """,
        ("`<<value>>`", 'process.env.<<KEY>> ?? ""'),
        (),
    ),
    _code(
        "code.typescript.environment_de", "de", "holdout", "typescript",
        """
        // Umgebung: Produktion
        export const environment = {
          production: true,
          apiBaseUrl: "https://api.example.de",
          <<keyCamel>>: '<<value>>',
        };
        """,
        ("'<<value>>'", "import.meta.env.VITE_<<KEY>>"),
    ),
    _code(
        "code.go.struct_de", "de", "holdout", "go",
        """
        // Konfiguration des Abgleichdienstes
        var cfg = Config{
        \tEndpoint: "https://api.example.de/v1",
        \tTimeout:  30 * time.Second,
        \t<<KeyPascal>>: `<<value>>`,
        }
        """,
        ("`<<value>>`", 'os.Getenv("<<KEY>>")'),
        (),
    ),
    _code(
        "code.java.spring", "en", "holdout", "java",
        """
        // credentials for the legacy adapter (to be replaced)
        @Configuration
        public class LegacyAdapterConfig {
            @Bean
            public LegacyClient legacyClient() {
                return LegacyClient.builder()
                        .endpoint("https://legacy.example.com/soap")
                        .<<keyCamel>>("<<value>>")
                        .build();
            }
        }
        """,
        ('"<<value>>"', 'System.getenv("<<KEY>>")'),
    ),
    _code(
        "code.csharp.verbatim", "en", "holdout", "csharp",
        """
        // service options for the test setup
        var options = new ServiceOptions
        {
            Endpoint = new Uri("https://api.example.com/"),
            <<KeyPascal>> = @"<<value>>",
            Retries = 3,
        };
        """,
        ('@"<<value>>"', 'configuration["<<KeyPascal>>"]'),
        (),
    ),
    _code(
        "code.rust.raw_string", "en", "holdout", "rust",
        """
        // test configuration for the import service
        fn config() -> Config {
            Config {
                endpoint: "https://import.example.com".into(),
                <<key>>: r#"<<value>>"#.into(),
                retries: 3,
            }
        }
        """,
        ('r#"<<value>>"#.into()', 'std::env::var("<<KEY>>").unwrap_or_default()'),
        (),
    ),
    _code(
        "code.ruby.initializer_de", "de", "holdout", "ruby",
        """
        # Initialisierer für den Zahlungsanbieter
        Rails.application.configure do
          config.x.zahlung.endpunkt = "https://pay.example.de"
          config.x.zahlung.<<key>> = '<<value>>'
        end
        """,
        ("'<<value>>'", 'ENV["<<KEY>>"]'),
        (),
    ),
    _prose(
        "chat.en.incident", "chat", "en", "holdout",
        """
        Priya Nair 14:02
        Deployment failed again with 401 🙃

        Jonas Becker 14:05
        My bad, the old <<label>> expired. New one → <<value>>
        Can you retry the pipeline?
        """,
        ("<<value>>", "{{ <<key>> }} from the shared vault"),
    ),
    _prose(
        "chat.de.import", "chat", "de", "holdout",
        """
        Sabine Hoffmann 11:20
        Der Import bricht mit „unauthorized“ ab 😬

        Murat Yilmaz 11:24
        Ich hab den Zugang erneuert (<<label>>): <<value>>
        Bitte nicht ins Wiki kopieren.
        """,
        ("<<value>>", "liegt jetzt als {{ <<key>> }} im Team-Vault"),
    ),
    _prose(
        "ticket.en.portal", "ticket", "en", "holdout",
        """
        SUP-1182: Customer cannot log in to reporting portal
        Status: In Progress · Assignee: k.osei
        ---
        Comment (support-l2): Reset done. Temporary <<label>> for the customer is <<value>> — please ask them to change it after first login.
        """,
        ("<<value>>", "available to them via ${<<KEY>>} in the onboarding sheet"),
    ),
    _prose(
        "ticket.de.lager", "ticket", "de", "holdout",
        """
        SD-7740: Zugang für neue Kollegin im Lager
        Status: Erledigt – Bearbeiter: IT-Servicedesk
        ---
        Kommentar: Zugang eingerichtet. <<label>>: <<value>>. Muss beim ersten Login geändert werden.
        """,
        ("<<value>>", "siehe Variable ${<<KEY>>} im Onboarding-Skript"),
    ),
    _prose(
        "mail.en.vendor", "mail", "en", "holdout",
        """
        -------- Forwarded Message --------
        Subject: Re: access for vendor onboarding
        From: support@vendor.example
        To: procurement@example.com

        Hello,

        please find your <<label>> below. Store it securely.

        <<label>>: <<value>>

        Kind regards,
        Vendor Support
        """,
        ("<<value>>", "${<<KEY>>} (we will send the value separately)"),
    ),
    _prose(
        "mail.de.portal", "mail", "de", "holdout",
        """
        Betreff: WG: Ihr Zugang zum Lieferantenportal

        Sehr geehrte Damen und Herren,

        Ihre Zugangsdaten für das Lieferantenportal (<<label>>): <<value>>
        Aus Sicherheitsgründen empfehlen wir, diese E-Mail nach Kenntnisnahme zu löschen.

        Mit freundlichen Grüßen
        Ihr Portal-Team
        """,
        ("<<value>>", "${<<KEY>>} (wird Ihnen separat per Post zugestellt)"),
    ),
)


PROFILES = {
    "dlp_anthropic_key": Profile("llm.anthropic.api_key", "API_KEY", "secret", "anthropic_api_key", "Anthropic API key", "Anthropic-API-Schlüssel"),
    "dlp_openai_key": Profile("llm.openai.api_key", "API_KEY", "secret", "openai_api_key", "OpenAI API key", "OpenAI-API-Schlüssel"),
    "dlp_openai_legacy": Profile("llm.openai.api_key", "API_KEY", "secret", "openai_api_key", "legacy OpenAI API key", "alter OpenAI-API-Schlüssel"),
    "dlp_openai_svc": Profile("llm.openai.api_key", "API_KEY", "secret", "openai_service_account_key", "OpenAI service account key", "OpenAI-Service-Account-Key"),
    "dlp_huggingface": Profile("llm.huggingface.token", "API_KEY", "secret", "hf_token", "Hugging Face token", "Hugging-Face-Token"),
    "dlp_groq_key": Profile("llm.groq.api_key", "API_KEY", "secret", "groq_api_key", "Groq API key", "Groq-API-Key"),
    "dlp_xai_key": Profile("llm.xai.api_key", "API_KEY", "secret", "xai_api_key", "xAI API key", "xAI-API-Key"),
    "dlp_replicate": Profile("llm.replicate.api_token", "API_KEY", "secret", "replicate_api_token", "Replicate API token", "Replicate-API-Token"),
    "dlp_aws_access_key": Profile("cloud.aws.access_key_id", "CLOUD_KEY", "secret", "aws_access_key_id", "AWS access key ID", "AWS-Access-Key-ID"),
    "dlp_aws_secret_key": Profile("cloud.aws.secret_access_key", "CLOUD_KEY", "secret", "aws_secret_access_key", "AWS secret access key", "AWS-Secret-Access-Key"),
    "dlp_google_api_key": Profile("cloud.gcp.api_key", "CLOUD_KEY", "secret", "google_maps_api_key", "Google Maps API key", "Google-Maps-API-Schlüssel"),
    "dlp_google_oauth_token": Profile("cloud.gcp.oauth_access_token", "CLOUD_KEY", "secret", "google_access_token", "Google OAuth access token", "Google-OAuth-Access-Token"),
    "dlp_gcp_client_secret": Profile("cloud.gcp.oauth_client_secret", "CLOUD_KEY", "secret", "google_client_secret", "Google OAuth client secret", "Google-OAuth-Client-Secret"),
    "dlp_github_token": Profile("vcs.github.token", "SECRET_TOKEN", "secret", "github_token", "GitHub token", "GitHub-Token"),
    "dlp_github_pat": Profile("vcs.github.fine_grained_pat", "SECRET_TOKEN", "secret", "gh_token", "GitHub fine-grained token", "GitHub-Fine-grained-Token"),
    "dlp_gitlab_pat": Profile("vcs.gitlab.pat", "SECRET_TOKEN", "secret", "gitlab_token", "GitLab access token", "GitLab-Zugriffstoken"),
    "dlp_gitlab_token": Profile("vcs.gitlab.token", "SECRET_TOKEN", "secret", "gitlab_deploy_token", "GitLab deploy token", "GitLab-Deploy-Token"),
    "dlp_gitlab_oauth_secret": Profile(
        "vcs.gitlab.oauth_app_secret", "API_KEY", "secret", "gitlab_oauth_secret", "GitLab OAuth application secret",
        "GitLab-OAuth-Anwendungs-Secret",
    ),
    "dlp_npm_token": Profile("registry.npm.access_token", "SECRET_TOKEN", "secret", "npm_token", "npm token", "npm-Token"),
    "dlp_stripe_key": Profile("payment.stripe.secret_key", "PAYMENT_KEY", "secret", "stripe_secret_key", "Stripe secret key", "Stripe-Secret-Key"),
    "dlp_stripe_webhook": Profile("payment.stripe.webhook_secret", "PAYMENT_KEY", "secret", "stripe_webhook_secret", "Stripe webhook secret", "Stripe-Webhook-Secret"),
    "dlp_slack_token": Profile("comm.slack.token", "SECRET_TOKEN", "secret", "slack_token", "Slack token", "Slack-Token"),
    "dlp_discord_token": Profile("comm.discord.bot_token", "SECRET_TOKEN", "secret", "discord_bot_token", "Discord bot token", "Discord-Bot-Token"),
    "dlp_eth_private_key": Profile("crypto.ethereum.private_key", "CRYPTO_KEY", "secret", "wallet_private_key", "wallet private key", "Wallet-Private-Key"),
    "dlp_btc_wif": Profile("crypto.bitcoin.wif", "CRYPTO_KEY", "secret", "btc_wif_key", "Bitcoin WIF key", "Bitcoin-WIF-Schlüssel"),
    "dlp_private_key_block": Profile("key.pem_private_key", "PRIVATE_KEY", "secret", "tls_private_key", "TLS private key", "privater TLS-Schlüssel"),
    "dlp_private_key_header": Profile("key.pem_private_key", "PRIVATE_KEY", "fragment", "ssh_private_key", "SSH private key", "privater SSH-Schlüssel"),
    "dlp_jwt_token": Profile("token.jwt", "SECRET_TOKEN", "secret", "id_token", "ID token", "ID-Token"),
    "dlp_credential_in_url": Profile(
        "credential.url_query_secret", "CREDENTIAL", "secret", "export_url", "export link", "Export-Link",
        "https://api.example.com/v1/export?format=csv&api_key=<<value>>",
    ),
    "dlp_env_var_secret": Profile("credential.secret_assignment", "CREDENTIAL", "secret", "service_secret", "service secret", "Dienst-Secret"),
    "dlp_password_assignment": Profile("credential.password_assignment", "CREDENTIAL", "secret", "db_password", "database password", "Datenbank-Passwort"),
    "dlp_generic_credential_assignment": Profile("credential.secret_assignment", "CREDENTIAL", "secret", "client_secret", "client secret", "Client-Secret"),
    "dlp_bearer_token": Profile(
        "credential.http_bearer", "SECRET_TOKEN", "secret", "authorization", "access token", "Access-Token", "Bearer <<value>>"
    ),
    "dlp_basic_auth": Profile(
        "credential.http_basic_auth", "CREDENTIAL", "secret", "proxy_authorization", "proxy credentials", "Proxy-Zugangsdaten",
        "Basic <<value>>",
    ),
    "dlp_signed_url_signature": Profile(
        "credential.signed_url_signature", "CREDENTIAL", "secret", "report_url", "download link", "Download-Link",
        "https://reports.s3.eu-central-1.amazonaws.com/q3.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=<<value>>",
    ),
    "dlp_session_cookie": Profile(
        "credential.session_cookie", "CREDENTIAL", "secret", "session_cookie", "session cookie", "Session-Cookie",
        {
            "java_session_id": "JSESSIONID=<<value>>",
            "php_session_id": "PHPSESSID=<<value>>",
            "express_session_id": "connect.sid=<<value>>",
            "laravel_session": "laravel_session=<<value>>",
        },
    ),
    "dlp_csrf_token": Profile("credential.csrf_token", "SECRET_TOKEN", "secret", "csrf_token", "CSRF token", "CSRF-Token"),
    "dlp_password_hash": Profile("credential.password_hash", "PASSWORD_HASH", "secret", "password_hash", "password hash", "Passwort-Hash"),
    "dlp_url_userinfo_password": Profile(
        "credential.url_userinfo", "CREDENTIAL", "secret", "database_url", "database URL", "Datenbank-URL",
        "postgres://app:<<value>>@db.internal:5432/app",
    ),
    "dlp_url_userinfo_token": Profile(
        "credential.url_userinfo_token", "SECRET_TOKEN", "secret", "git_remote", "repository URL", "Repository-URL",
        "https://<<value>>:x-oauth-basic@github.com/acme/app.git",
    ),
    "dlp_connection_string_password": Profile(
        "credential.connection_string", "CREDENTIAL", "secret", "connection_string", "connection string",
        "Verbindungszeichenfolge", "Server=db.internal;Database=app;User Id=app;Password=<<value>>;",
    ),
    "dlp_ldap_bind_password": Profile(
        "credential.ldap_bind_password", "CREDENTIAL", "secret", "ldap_bind", "LDAP bind", "LDAP-Bind",
        "ldapsearch -x -D cn=svc,dc=acme,dc=org -w <<value>>",
    ),
    "dlp_de_vat_id": Profile("identifier.de.vat_id", "dlp.de.vat_id", "identifier", "vat_id", "VAT ID", "USt-IdNr."),
    "dlp_de_commercial_register_number": Profile(
        "identifier.de.commercial_register", "dlp.de.commercial_register_number", "identifier", "commercial_register",
        "commercial register number", "Handelsregisternummer",
    ),
    "dlp_de_facility_number_bsnr": Profile(
        "identifier.de.bsnr", "dlp.de.facility_number_bsnr", "identifier", "bsnr", "facility number (BSNR)",
        "Betriebsstättennummer (BSNR)",
    ),
    "dlp_record_case_id": Profile("identifier.record.case", "dlp.record.case_id", "identifier", "case_id", "case ID", "Aktenzeichen"),
    "dlp_record_contract_id": Profile(
        "identifier.record.contract", "dlp.record.contract_id", "identifier", "contract_id", "contract ID", "Vertragsnummer"
    ),
    "dlp_record_claim_id": Profile("identifier.record.claim", "dlp.record.claim_id", "identifier", "claim_id", "claim ID", "Schadennummer"),
    "dlp_record_order_id": Profile("identifier.record.order", "dlp.record.order_id", "identifier", "order_id", "order ID", "Bestellnummer"),
    "dlp_record_invoice_id": Profile(
        "identifier.record.invoice", "dlp.record.invoice_id", "identifier", "invoice_id", "invoice ID", "Rechnungsnummer"
    ),
    "dlp_project_id": Profile("identifier.project", "dlp.project_id", "identifier", "project_id", "project ID", "Projekt-ID"),
    "dlp_organization_id": Profile("identifier.organization", "dlp.organization_id", "identifier", "tenant_id", "tenant ID", "Mandanten-ID"),
    # Baseline entities (GOLD-D2): no ARK rule yet, keyed by their entity id.
    "comm.slack.app_config_token": Profile(
        "comm.slack.app_config_token", "SECRET_TOKEN", "secret", "slack_app_token", "Slack app token", "Slack-App-Token"
    ),
    "comm.webhook_url": Profile(
        "comm.webhook_url", "SECRET_TOKEN", "secret", "notify_webhook_url", "chat webhook URL", "Chat-Webhook-URL"
    ),
    "comm.discord.api_credentials": Profile(
        "comm.discord.api_credentials", "API_KEY", "secret", "discord_client_secret", "Discord client secret",
        "Discord-Client-Secret",
    ),
    "comm.telegram.bot_token": Profile(
        "comm.telegram.bot_token", "SECRET_TOKEN", "secret", "telegram_bot_token", "Telegram bot token", "Telegram-Bot-Token"
    ),
    "comm.twilio.api_key": Profile("comm.twilio.api_key", "API_KEY", "secret", "twilio_api_key", "Twilio API key", "Twilio-API-Key"),
    "comm.sendgrid.api_key": Profile(
        "comm.sendgrid.api_key", "API_KEY", "secret", "sendgrid_api_key", "SendGrid API key", "SendGrid-API-Key"
    ),
    "comm.brevo.api_key": Profile("comm.brevo.api_key", "API_KEY", "secret", "brevo_api_key", "Brevo API key", "Brevo-API-Key"),
    "comm.mailgun.key": Profile("comm.mailgun.key", "API_KEY", "secret", "mailgun_api_key", "Mailgun API key", "Mailgun-API-Key"),
    "comm.mailchimp.api_key": Profile(
        "comm.mailchimp.api_key", "API_KEY", "secret", "mailchimp_api_key", "Mailchimp API key", "Mailchimp-API-Key"
    ),
    "comm.messagebird.api_token": Profile(
        "comm.messagebird.api_token", "API_KEY", "secret", "messagebird_api_key", "MessageBird API key", "MessageBird-API-Key"
    ),
    "comm.mattermost.access_token": Profile(
        "comm.mattermost.access_token", "API_KEY", "secret", "mattermost_access_token", "Mattermost access token",
        "Mattermost-Zugriffstoken",
    ),
    "comm.sendbird.access_token": Profile(
        "comm.sendbird.access_token", "API_KEY", "secret", "sendbird_api_token", "Sendbird API token", "Sendbird-API-Token"
    ),
    "comm.gitter.access_token": Profile(
        "comm.gitter.access_token", "API_KEY", "secret", "gitter_token", "Gitter token", "Gitter-Token"
    ),
    "identity.okta.access_token": Profile(
        "identity.okta.access_token", "SECRET_TOKEN", "secret", "okta_api_token", "Okta API token", "Okta-API-Token"
    ),
    "identity.authress.access_key": Profile(
        "identity.authress.access_key", "SECRET_TOKEN", "secret", "authress_access_key", "Authress access key",
        "Authress-Zugriffsschlüssel",
    ),
    "identity.onepassword.secret": Profile(
        "identity.onepassword.secret", "SECRET_TOKEN", "secret", "op_secret", "1Password secret", "1Password-Secret"
    ),
    "commerce.shipping.api_token": Profile(
        "commerce.shipping.api_token", "API_KEY", "secret", "shipping_api_key", "shipping API key", "Versand-API-Schlüssel"
    ),
}


# Placeholder values for the "placeholder" hard negative; key markers are resolved.
PLACEHOLDERS = {
    "en": (
        "<your-<<key-kebab>>>",
        "YOUR_<<KEY>>_HERE",
        "changeme",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "REPLACE_ME",
        "TODO",
        "********",
    ),
    "de": (
        "<dein-<<key-kebab>>>",
        "HIER_<<KEY>>_EINTRAGEN",
        "BITTE_AENDERN",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "<wird-nachgereicht>",
        "********",
    ),
}

# Key and labels (en, de) of the "lookalike" hard negative: a neutral identifier field.
LOOKALIKE_KEY = ("correlation_id", "correlation ID", "Korrelations-ID")

# Fill words for the "doc_example" and "test_key" hard negatives: the first word whose
# characters all lie in a segment's alphabet is repeated over the segment.
FILL_WORDS = {
    "doc_example": ("EXAMPLEKEY", "examplekey", "EXAMPLE", "example", "deadbeef", "DEADBEEF", "0123456789"),
    "test_key": ("TESTKEY", "testkey", "TEST", "test", "1234567890"),
}
