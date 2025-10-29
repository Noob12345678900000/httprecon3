#!/usr/bin/env python3
"""
httprecon3.py - Advanced Recon Crawler
Features: Crawl, Keywords, API Keys, Subdomains, Screenshots, Stealth
"""

import requests
from bs4 import BeautifulSoup
import cssutils
import re
import argparse
import json
import sys
import os
import time
import random
import socket
from urllib.parse import urlparse, urljoin
from collections import defaultdict
import logging
from colorama import init, Fore, Style
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from dns.resolver import Resolver
import threading

init(autoreset=True)
cssutils.log.setLevel(logging.CRITICAL)

# === CONFIG ===
BASE_HEADERS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
]
TIMEOUT = 10
MAX_DEPTH = 3
DELAY_MIN = 1.0
DELAY_MAX = 3.0

# === SUBDOMAIN WORDLIST (150+ common, devops, infra, business, legacy) ===
SUBDOMAIN_WORDLIST = [
    # === CORE & COMMON (1–40) ===
    'www', 'api', 'app', 'auth', 'admin', 'dashboard', 'blog', 'image', 'cdn', 'static',
    'dev', 'test', 'staging', 'prod', 'beta', 'mail', 'webmail', 'ftp', 'db', 'mysql',
    'redis', 'mongo', 'ns1', 'ns2', 'mx', 'smtp', 'login', 'secure', 'portal', 'vpn',
    'backup', 'logs', 'monitor', 'status', 'health', 'metrics', 'grafana', 'kibana',
    'jenkins', 'gitlab', 'docker', 'k8s', 'prometheus', 'elastic', 'console', 'panel',

    # === API & MICROSERVICES (41–70) ===
    'api2', 'api3', 'v1', 'v2', 'v3', 'graphql', 'rest', 'rpc', 'gateway', 'proxy',
    'edge', 'authz', 'oauth', 'openid', 'sso', 'identity', 'users', 'accounts', 'billing',
    'payments', 'orders', 'cart', 'checkout', 'search', 'recommend', 'catalog', 'inventory',
    'warehouse', 'shipping', 'tracking', 'notifications', 'events', 'webhook', 'callback',
    'worker', 'queue', 'jobs', 'tasks', 'scheduler', 'cron', 'batch', 'import', 'export',

    # === INFRA & DEVOPS (71–100) ===
    'ci', 'cd', 'build', 'deploy', 'release', 'registry', 'harbor', 'nexus', 'artifactory',
    'sonarqube', 'sonar', 'code', 'repo', 'repos', 'source', 'git', 'svn', 'hg', 'bitbucket',
    'perforce', 'vault', 'secrets', 'config', 'cfg', 'env', 'configserver', 'eureka', 'consul',
    'zookeeper', 'etcd', 'kafka', 'rabbitmq', 'nats', 'pulsar', 'activemq', 'broker', 'pubsub',
    'cache', 'memcached', 'varnish', 'nginx', 'traefik', 'haproxy', 'lb', 'loadbalancer', 'ingress',

    # === MONITORING & OBSERVABILITY (101–120) ===
    'alert', 'alerts', 'alertmanager', 'uptime', 'ping', 'probe', 'blackbox', 'loki', 'tempo',
    'jaeger', 'zipkin', 'trace', 'tracing', 'opentelemetry', 'otel', 'sentry', 'datadog', 'newrelic',
    'dynatrace', 'appdynamics', 'log', 'logstash', 'fluentd', 'syslog', 'splunk', 'sumologic',

    # === SECURITY & COMPLIANCE (121–140) ===
    'sec', 'security', 'waf', 'firewall', 'ids', 'ips', 'scan', 'scanner', 'nessus', 'qualys',
    'burp', 'zaproxy', 'owasp', 'csp', 'hsts', 'ssl', 'tls', 'cert', 'certificate', 'pki',
    'ca', 'rootca', 'iam', 'policy', 'audit', 'compliance', 'gdpr', 'hipaa', 'soc2', 'iso27001',

    # === BUSINESS & MARKETING (141–160) ===
    'shop', 'store', 'ecommerce', 'market', 'marketing', 'campaign', 'ads', 'adwords', 'analytics',
    'ga', 'tagmanager', 'gtm', 'pixel', 'crm', 'sales', 'support', 'help', 'kb', 'docs',
    'wiki', 'forum', 'community', 'press', 'news', 'media', 'assets', 'files', 'download', 'upload',

    # === LEGACY & MISC (161–180) ===
    'old', 'legacy', 'archive', 'demo', 'sandbox', 'playground', 'lab', 'labs', 'research', 'devops',
    'internal', 'private', 'corp', 'intranet', 'extranet', 'partner', 'vendor', 'client', 'customer',
    'employee', 'hr', 'payroll', 'finance', 'accounting', 'legal', 'it', 'noc', 'soc', 'helpdesk',

    # === CLOUDS & CDNs (181–200) ===
    'aws', 'gcp', 'azure', 'cloud', 'cloudfront', 'akamai', 'fastly', 'cloudflare', 'imperva', 'incapsula',
    's3', 'storage', 'bucket', 'blob', 'fileserver', 'nfs', 'cifs', 'share', 'sync', 'backup1',
    'backup2', 'dr', 'disaster', 'recovery', 'replica', 'mirror', 'failover', 'lb1', 'lb2', 'node1',

    # === DATABASE & CACHING (201–220) ===
    'postgres', 'postgresql', 'psql', 'oracle', 'mssql', 'sqlserver', 'cassandra', 'couchbase', 'dynamodb',
    'bigtable', 'spanner', 'aurora', 'rds', 'atlas', 'cosmos', 'influx', 'timeseries', 'tsdb', 'graph',
    'neo4j', 'arangodb', 'dgraph', 'janus', 'titan', 'orientdb', 'couchdb', 'riak', 'hbase', 'hadoop',

    # === MESSAGING & STREAMING (221–240) ===
    'stream', 'streams', 'ingest', 'realtime', 'rt', 'ws', 'websocket', 'socket', 'mqtt', 'amqp',
    'stomp', 'redis-pubsub', 'kafka-connect', 'flink', 'spark', 'storm', 'heron', 'samza', 'kinesis',
    'firehose', 'pubsub', 'eventhub', 'servicebus', 'sqs', 'sns', 'cloudwatch', 'cloudtrail', 'guardduty',

    # === TESTING & QA (241–250) ===
    'qa', 'uat', 'integration', 'e2e', 'perf', 'load', 'stress', 'smoke', 'canary', 'feature'
]

# === 300+ SENSITIVE DATA & VULNERABILITY PATTERNS (INCLUDING USER-PROVIDED) ===
API_KEY_PATTERNS = {
    # === ORIGINAL 100+ (1–100) ===
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'(?i)aws(.{0,20})?(?-i)[\'\"][0-9a-zA-Z\/+]{40}[\'\"]',
    'Supabase URL': r'https://[a-z0-9-]+\.supabase\.co',
    'Supabase Anon Key': r'(?i)(?:anon|public).*?["\'][a-zA-Z0-9]{40,}["\']',
    'Supabase Service Key': r'(?i)service_role.*?["\'][a-zA-Z0-9]{40,}["\']',
    'Firebase API Key': r'["\']apiKey["\']\s*:\s*["\'][a-zA-Z0-9_-]{39}["\']',
    'Firebase Project ID': r'["\']projectId["\']\s*:\s*["\'][a-zA-Z0-9-]{12,}[\'"]',
    'Firebase App ID': r'["\']appId["\']\s*:\s*["\']1:[0-9]+:web:[a-f0-9]+["\']',
    'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google OAuth': r'ya29\.[0-9A-Za-z\-_]+',
    'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
    'Slack Token': r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    'JWT Token': r'eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'GitHub PAT': r'github_pat_[a-zA-Z0-9_]{82}',
    'Heroku API Key': r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'OpenAI API Key': r'sk-[a-zA-Z0-9]{48}',
    'MongoDB URI': r'mongodb(\+srv)?:\/\/[^:]+:[^@]+@',
    'S3 Bucket': r'[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com',
    'Cloudflare Token': r'[a-zA-Z0-9_-]{40}',
    'Discord Webhook': r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+',
    'Telegram Bot Token': r'\d{8,10}:[a-zA-Z0-9_-]{35}',
    'Generic API Key': r'(?i)api[-_]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{16,64}["\']?',
    'Private IP': r'\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)[0-9]+\.[0-9]+\b',
    'SSH Key': r'-----BEGIN [DR]SA PRIVATE KEY-----',
    'JWT Secret': r'(?i)secret\s*[:=]\s*["\'][a-zA-Z0-9._-]{10,}["\']',
    'Basic Auth': r'Basic [a-zA-Z0-9+/=]{20,}',
    'Bearer Token': r'Bearer [a-zA-Z0-9._-]{20,}',
    'X-API-Key': r'X-API-Key: [a-zA-Z0-9_-]{20,}',
    'Admin Panel': r'/admin|/wp-admin|/phpmyadmin',
    'Backup File': r'\.(bak|old|~|swp|backup)',
    'Env File': r'\.env(?:\.local|\.prod)?',
    'Git Exposed': r'/\.git/(HEAD|config)',
    'Debug Mode': r'debug=true|DEBUG=1',
    'GraphQL': r'/graphql',
    'Open Redirect': r'redirect=|url=|next=',
    'SQL Error': r'SQL syntax|mysql_fetch|ORA-',
    'Stack Trace': r'Traceback \(most recent call last\):',
    'Laravel Debug': r'Whoops, looks like something went wrong',
    'Django Debug': r'DoesNotExist|TemplateDoesNotExist',
    'WordPress Error': r'require_once|Call to undefined function',
    'Version Leak': r'X-Powered-By|Server:',
    'CORS *': r'Access-Control-Allow-Origin: \*',
    'Missing CSP': r'(?i)missing: content-security-policy',
    'Crypto Wallet': r'(0x)?[a-fA-F0-9]{40}',
    'Ethereum Key': r'[a-f0-9]{64}',
    'IBAN': r'[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}',
    'Credit Card': r'\b(?:\d[ -]*?){13,16}\b',
    'SSN': r'\b\d{3}-\d{2}-\d{4}\b',

    # === ADDITIONAL 100 (101–200) ===
    'Twilio SID': r'AC[a-f0-9]{32}',
    'Twilio Auth Token': r'[a-f0-9]{32}',
    'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    'Mailgun Private Key': r'key-[0-9a-zA-Z]{32}',
    'PayPal Client ID': r'A[0-9a-zA-Z]{14}_[0-9a-zA-Z]{14}',
    'PayPal Secret': r'E[0-9a-zA-Z]{76}',
    'NPM Token': r'(?:npm_)[a-zA-Z0-9]{36}',
    'PyPI Token': r'pypi-[A-Za-z0-9_-]{40}',
    'Docker Hub Token': r'[a-z0-9]{64}',
    'DigitalOcean Token': r'dop_v1_[a-f0-9]{64}',
    'Linode API Key': r'[a-f0-9]{64}',
    'Vultr API Key': r'[A-Z0-9]{32}',
    'Hetzner Token': r'[a-zA-Z0-9]{36}',
    'Railway API Key': r'rw_[a-zA-Z0-9]{40}',
    'Render API Key': r'render_[a-zA-Z0-9]{40}',
    'Vercel Token': r'[a-zA-Z0-9]{24}',
    'Netlify Token': r'[a-zA-Z0-9]{40}',
    'Shopify Private App': r'shppa_[a-f0-9]{32}',
    'Shopify Shared Secret': r'shpss_[a-f0-9]{32}',
    'LinkedIn Client ID': r'[0-9a-z]{14}',
    'LinkedIn Secret': r'[0-9a-z]{16}',
    'Dropbox Token': r'sl\.[A-Za-z0-9\-_]{135}',
    'Asana Token': r'[0-9]+\.[0-9a-zA-Z]{40}',
    'Trello API Key': r'[a-f0-9]{32}',
    'Airtable API Key': r'key[a-zA-Z0-9]{14}',
    'Notion Token': r'secret_[a-zA-Z0-9]{43}',
    'Figma Token': r'[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'Mapbox Token': r'(pk|sk)\.eyJ1Ijoi[a-zA-Z0-9]+\.eyJ[0-9a-zA-Z]+',
    'Algolia API Key': r'[a-f0-9]{32}',
    'Sentry DSN': r'https://[a-f0-9]+@sentry\.io/\d+',
    'Datadog API Key': r'[a-f0-9]{32}',
    'New Relic License': r'[a-f0-9]{40}',
    'Rollbar Token': r'post_[a-z0-9]{32}',
    'Bugsnag Key': r'[a-f0-9]{32}',
    'Loggly Token': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'Papertrail Token': r'[a-z0-9]{40}',
    'Amplitude Key': r'[a-f0-9]{32}',
    'Mixpanel Token': r'[a-f0-9]{32}',
    'Segment Key': r'[a-zA-Z0-9]{22}',
    'Intercom Key': r'[a-zA-Z0-9]{32}',
    'HubSpot Key': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'Zendesk Token': r'[a-zA-Z0-9]{40}',
    'Freshdesk Key': r'[a-zA-Z0-9]{20}',
    'Pipedrive Token': r'[a-f0-9]{40}',
    'Salesforce Token': r'[0-9A-Za-z]{35}',
    'Okta Token': r'00D[a-zA-Z0-9]{15}',
    'Auth0 Client Secret': r'[a-zA-Z0-9_-]{44}',
    'Firebase Auth Domain': r'[\w-]+\.firebaseapp\.com',
    'Firebase Storage Bucket': r'[\w-]+\.appspot\.com',
    'GCP Service Account': r'\"type\": \"service_account\"',
    'Azure Client ID': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'Azure Tenant ID': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'Azure Subscription ID': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'Azure Storage Key': r'[A-Za-z0-9+/]{86}==',
    'Kubernetes Secret': r'apiVersion: v1\nkind: Secret',
    'Docker Config': r'\"auths\":\s*\{',
    'Nginx Config Leak': r'nginx/\d+\.\d+',
    'Apache Config': r'Apache/[\d\.]+',
    'PHP Info': r'<\?php.*phpinfo',
    'Laravel Config': r'APP_KEY=base64:',
    'Rails Secret': r'config.secret_key_base',
    'Django Secret': r'SECRET_KEY =',
    'Flask Secret': r'SECRET_KEY =',
    'Next.js Env': r'NEXT_PUBLIC_',
    'Nuxt Env': r'NUXT_ENV_',
    'SvelteKit Env': r'VITE_',
    'React Env': r'REACT_APP_',
    'Vue Env': r'VUE_APP_',
    'Angular Env': r'environment.ts',
    'Expo Config': r'expo\.constants',
    'Capacitor Config': r'capacitor.config.json',
    'Cordova Config': r'config.xml',
    'Ionic Config': r'ionic.config.json',
    'Electron Config': r'electron-builder',
    'Tauri Config': r'tauri.conf.json',
    'FastAPI Key': r'fastapi\.users',
    'GraphQL Introspection': r'__schema',
    'GraphQL Playground': r'/graphql\??.*playground',
    'Hasura Secret': r'HASURA_GRAPHQL_JWT_SECRET',
    'PostgREST Anon': r'POSTGREST_ANON_KEY',
    'Supabase JWT Secret': r'SUPABASE_JWT_SECRET',
    'Firebase Admin SDK': r'firebase-admin',
    'Google Service Account JSON': r'\"private_key\":',
    'AWS Config File': r'aws_access_key_id',
    'GCP Credentials': r'google\.application_credentials',
    'Azure AD App Secret': r'client_secret',
    'OAuth Redirect URI': r'redirect_uri=',
    'Open Redirect Param': r'url=',
    'SSRF Param': r'@',
    'Path Traversal': r'\.\./',
    'LFI': r'/etc/passwd',
    'RFI': r'http://',
    'Command Injection': r';|\||&',
    'XSS Payload': r'<script>',
    'SQLi Payload': r'\'\s+OR',
    'NoSQL Injection': r'{\"\\$ne\":null',
    'JWT None Alg': r'\"alg\":\s*\"none\"',
    'JWT Weak Secret': r'\"secret\"|\'123456\'',
    'CORS Misconfig': r'Access-Control-Allow-Origin: \*$',
    'HSTS Missing': r'(?!.*Strict-Transport-Security)',
    'X-Frame-Options Missing': r'(?!.*X-Frame-Options)',
    'CSP Missing': r'(?!.*Content-Security-Policy)',
    'Clickjacking': r'<frame|<iframe',
    'Open S3 Bucket': r'\"ListBucketResult\"',
    'Exposed .git': r'refs/heads/',
    'Exposed .env': r'DB_PASSWORD=',
    'Exposed Backup': r'\.sql\.gz',
    'Exposed DS_Store': r'\.DS_Store',
    'Exposed IDE': r'\.idea/|\.vscode/',
    'Exposed Logs': r'\.log$',
    'Exposed Docker': r'Dockerfile',
    'Exposed Kubernetes': r'kind: Pod',
    'Exposed Terraform': r'\.tfstate',
    'Exposed Jenkins': r'Jenkinsfile',
    'Exposed CI/CD': r'pipeline:|workflow:',
    'Exposed Swagger': r'/swagger-ui',
    'Exposed API Docs': r'/api-docs',
    'Exposed GraphiQL': r'/graphiql',
    'Exposed Adminer': r'/adminer.php',
    'Exposed phpinfo': r'/phpinfo.php',
    'Exposed Server Status': r'/server-status',
    'Exposed .htaccess': r'RewriteRule',
    'Exposed Web.config': r'<configuration>',
    'Exposed robots.txt': r'Disallow: /admin',
    'Exposed sitemap.xml': r'<urlset',
    'Exposed favicon.ico': r'favicon.ico',
    'Exposed humans.txt': r'humanstxt',
    'Exposed security.txt': r'Contact:',
    'Exposed .well-known': r'/.well-known/',
    'Exposed OAuth': r'client_id',
    'Exposed JWT': r'eyJ',
    'Exposed API Key': r'[A-Za-z0-9]{32}',

    # === USER-PROVIDED PATTERNS (201–300+) ===
    'Cloudinary': r'cloudinary://.*',
    'Firebase URL': r'.*firebaseio\.com',
    'Slack Token': r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
    'RSA private key': r'-----BEGIN RSA PRIVATE KEY-----',
    'SSH (DSA) private key': r'-----BEGIN DSA PRIVATE KEY-----',
    'SSH (EC) private key': r'-----BEGIN EC PRIVATE KEY-----',
    'PGP private key block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Amazon AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
    'Amazon MWS Auth Token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'AWS API Key': r'AKIA[0-9A-Z]{16}',
    'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Facebook OAuth': r'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|\"][0-9a-f]{32}[\'|\"]',
    'GitHub': r'[g|G][i|I][t|T][h|H][u|U][b|B].*[\'|\"][0-9a-zA-Z]{35,40}[\'|\"]',
    'Generic API Key': r'[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
    'Generic Secret': r'[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|\"][0-9a-zA-Z]{32,45}[\'|\"]',
    'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google Cloud Platform API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google Cloud Platform OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Google Drive API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google Drive OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Google (GCP) Service-account': r'\"type\": \"service_account\"',
    'Google Gmail API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google Gmail OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Google OAuth Access Token': r'ya29\\.[0-9A-Za-z\\-_]+',
    'Google YouTube API Key': r'AIza[0-9A-Za-z\\-_]{35}',
    'Google YouTube OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    'Heroku API Key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'Password in URL': r'[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"\'\\s]',
    'PayPal Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Picatic API Key': r'sk_live_[0-9a-z]{32}',
    'Slack Webhook': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Restricted API Key': r'rk_live_[0-9a-zA-Z]{24}',
    'Square Access Token': r'sq0atp-[0-9A-Za-z\\-_]{22}',
    'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\\-_]{43}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'Twitter Access Token': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
    'Twitter OAuth': r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|\"][0-9a-zA-Z]{35,44}[\'|\"]'
}

DEFAULT_KEYWORDS = [
    # === ORIGINAL 10 ===
    'api[_-]?key', 'secret', 'password', 'token', 'jwt', '/admin', '/api/', '/debug', '.env', '.git',

    # === CREDENTIALS & SECRETS (11–30) ===
    'apikey', 'api[_-]?secret', 'access[_-]?token', 'refresh[_-]?token', 'auth[_-]?token',
    'bearer', 'session[_-]?id', 'csrf[_-]?token', 'x[_-]?auth[_-]?token', 'private[_-]?key',
    'public[_-]?key', 'ssh[_-]?key', 'pgp[_-]?key', 'encryption[_-]?key', 'master[_-]?password',
    'root[_-]?password', 'db[_-]?password', 'mysql[_-]?password', 'postgres[_-]?password', 'mongo[_-]?password',

    # === CONFIG & BACKUP FILES (31–60) ===
    'config\\.php', 'config\\.js', 'config\\.json', 'settings\\.php', 'local\\.env',
    'env\\.local', 'env\\.development', 'env\\.production', '\\.env\\.backup', '\\.env\\.old',
    '\\.env\\.save', 'database\\.yml', 'database\\.config', 'wp-config\\.php', 'web\\.config',
    'htpasswd', '\\.htaccess', 'nginx\\.conf', 'apache2\\.conf', 'Dockerfile', 'docker-compose\\.yml',
    'docker-compose\\.yaml', 'dockerfile', 'Jenkinsfile', 'pipeline\\.groovy', 'build\\.gradle',
    'pom\\.xml', 'package\\.json', 'yarn\\.lock', 'composer\\.json', 'composer\\.lock',

    # === ADMIN PANELS & DEBUG (61–90) ===
    '/administrator', '/adminer', '/phpmyadmin', '/pma', '/myadmin', '/dbadmin', '/sql',
    '/webadmin', '/cpanel', '/controlpanel', '/login', '/signin', '/auth', '/oauth',
    '/dashboard', '/panel', '/manage', '/settings', '/config', '/setup', '/install',
    '/wp-admin', '/wp-login', '/wordpress', '/joomla', '/drupal', '/magento', '/laravel',
    '/symfony', '/rails', '/adminer\\.php', '/phpinfo', '/info\\.php', '/test\\.php',
    '/debug\\.php', '/dev', '/staging', '/beta', '/internal', '/private', '/secure',

    # === SOURCE CODE & VCS (91–110) ===
    '\\.git/', '\\.gitignore', '\\.gitconfig', '\\.git-credentials', '\\.svn/', '\\.hg/',
    '\\.bzr/', '\\.cvsignore', 'CVS/', 'src/', 'source/', 'app/', 'lib/', 'vendor/',
    'node_modules/', 'packages/', 'bin/', 'include/', 'inc/', 'core/', 'framework/',
    'system/', 'engine/', 'kernel/', 'boot/', 'runtime/', 'cache/', 'tmp/', 'temp/',

    # === BACKUP & ARCHIVES (111–130) ===
    '\\.bak$', '\\.old$', '\\.save$', '\\.backup$', '\\.swp$', '\\.swo$', '\\~.*',
    '\\.tar\\.gz$', '\\.zip$', '\\.rar$', '\\.7z$', '\\.sql$', '\\.sqlite$', '\\.db$',
    '\\.mdb$', '\\.accdb$', 'dump\\.sql', 'backup\\.sql', 'export\\.csv', 'data\\.json',

    # === API ENDPOINTS & WEBHOOKS (131–150) ===
    '/v1/', '/v2/', '/v3/', '/graphql', '/graphiql', '/altair', '/playground', '/webhook',
    '/callback', '/oauth2', '/sso', '/saml', '/openid', '/jwt', '/token', '/verify',
    '/reset', '/forgot', '/recover', '/health', '/status', '/metrics', '/ping', '/alive',

    # === LOGS & DEBUG (151–170) ===
    '\\.log$', 'error\\.log', 'access\\.log', 'debug\\.log', 'trace\\.log', 'server\\.log',
    'application\\.log', '/logs/', '/log/', 'var/log/', 'logfile', 'debug=true', 'debug=1',
    'trace=true', 'verbose=true', 'dev_mode', 'development=true', 'sandbox=true',

    # === CLOUD & INFRA (171–190) ===
    'aws_access_key_id', 'aws_secret_access_key', 'AWSSecretKey', 'AWS_SECRET_ACCESS_KEY',
    'cloudinary', 's3\\.amazonaws\\.com', 'digitalocean', 'heroku', 'firebase', 'supabase',
    'vercel', 'netlify', 'railway', 'render', 'fly\\.io', 'gcp', 'googleapis', 'azure',
    'cloudfront', 'storage\\.googleapis\\.com', 'appspot\\.com', 'blob\\.core\\.windows\\.net',

    # === PAYMENT & SENSITIVE (191–210) ===
    'stripe[_-]?key', 'stripe[_-]?secret', 'paypal[_-]?secret', 'paypal[_-]?client',
    'braintree', 'square', 'razorpay', 'paytm', 'midtrans', 'card[_-]?number', 'cvv',
    'cc[_-]?exp', 'billing', 'payment', 'checkout', 'subscription', 'plan', 'price',

    # === MISC VULNERABLE (211–250) ===
    '/backup/', '/old/', '/archive/', '/export/', '/download/', '/upload/', '/files/',
    '/assets/', '/static/', '/media/', '/images/', '/js/', '/css/', '/scripts/', '/lib/',
    '/includes/', '/modules/', '/plugins/', '/themes/', '/templates/', '/views/', '/controllers/',
    '/models/', '/routes/', '/middleware/', '/helpers/', '/utils/', '/tools/', '/bin/',
    'test\\.php', 'demo\\.php', 'example\\.php', 'sample\\.php', 'index\\.php\\?page=',
    'phpinfo\\.php', 'server-status', 'server-info', 'cgi-bin/', 'webdav', 'dav/',

    # === FINAL 50 PATTERNS (251–300) ===
    '\\.pem$', '\\.key$', '\\.crt$', '\\.cer$', '\\.ca$', '\\.pfx$', '\\.p12$',
    'id_rsa', 'id_dsa', 'known_hosts', 'authorized_keys', '\\.ovpn$', '\\.conf$',
    'credentials\\.json', 'service_account', 'firebase-config', 'google-service-account',
    'client_secrets\\.json', 'oauth-credentials', 'slack[_-]?token', 'discord[_-]?token',
    'telegram[_-]?bot', 'twilio[_-]?sid', 'sendgrid[_-]?key', 'mailgun[_-]?key',
    'ses[_-]?key', 'smtp[_-]?password', 'imap[_-]?password', 'ftp[_-]?password',
    'ssh[_-]?password', 'vpn[_-]?password', 'wifi[_-]?password', 'wpa[_-]?key',
    'passphrase', 'seed[_-]?phrase', 'mnemonic', 'private[_-]?key', 'keystore',
    'wallet\\.dat', 'wallet\\.json', 'keystore\\.jks', 'pkcs12', 'certificate',
    'license[_-]?key', 'serial[_-]?number', 'activation[_-]?code', 'product[_-]?key',
    'registration[_-]?key', 'auth[_-]?code', 'verification[_-]?code', 'otp[_-]?secret'
]

# === HELPERS ===
def get_random_headers():
    return {'User-Agent': random.choice(BASE_HEADERS)}

def normalize_url(base, url):
    return urljoin(base, url.strip())

def is_valid_url(url, base_domain):
    parsed = urlparse(url)
    return parsed.scheme in ('http', 'https') and parsed.netloc.endswith(base_domain)

def resolve_subdomain(sub, domain):
    try:
        full = f"{sub}.{domain}"
        socket.gethostbyname(full)
        return f"https://{full}"
    except:
        return None

def brute_force_subdomains(domain, wordlist=SUBDOMAIN_WORDLIST, threads=10):
    valid = []
    def worker(chunk):
        for sub in chunk:
            if (res := resolve_subdomain(sub, domain)):
                valid.append(res)
    chunks = [wordlist[i::threads] for i in range(threads)]
    ts = [threading.Thread(target=worker, args=(c,)) for c in chunks]
    for t in ts: t.start()
    for t in ts: t.join()
    return valid

def take_screenshot(url, output_dir='screenshots'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        total_height = driver.execute_script("return document.body.scrollHeight")
        driver.set_window_size(1920, total_height)
        filename = os.path.join(output_dir, f"{urlparse(url).netloc}_{int(time.time())}.png")
        driver.save_screenshot(filename)
        print(f"{Fore.GREEN}[+] Screenshot: {filename}")
    except Exception as e:
        print(f"{Fore.RED}[!] Screenshot failed: {url} → {e}")
    finally:
        driver.quit()

# === EXTENDED LINK EXTRACTION (50+ URL TYPES) ===
def extract_all_links(html, base_url, base_domain):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()

    # 1. <a href>
    for tag in soup.find_all('a', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 2. <link href>
    for tag in soup.find_all('link', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 3. <script src>
    for tag in soup.find_all('script', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 4. <img src>
    for tag in soup.find_all('img', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 5. <img srcset>
    for tag in soup.find_all('img', srcset=True):
        for src in tag['srcset'].split(','):
            url = src.strip().split()[0]
            links.add(normalize_url(base_url, url))

    # 6. <source src> / <source srcset>
    for tag in soup.find_all('source', src=True):
        links.add(normalize_url(base_url, tag['src']))
    for tag in soup.find_all('source', srcset=True):
        for src in tag['srcset'].split(','):
            url = src.strip().split()[0]
            links.add(normalize_url(base_url, url))

    # 7. <video src> / <video poster>
    for tag in soup.find_all('video', src=True):
        links.add(normalize_url(base_url, tag['src']))
    for tag in soup.find_all('video', poster=True):
        links.add(normalize_url(base_url, tag['poster']))

    # 8. <audio src>
    for tag in soup.find_all('audio', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 9. <track src>
    for tag in soup.find_all('track', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 10. <iframe src>
    for tag in soup.find_all('iframe', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 11. <frame src>
    for tag in soup.find_all('frame', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 12. <embed src>
    for tag in soup.find_all('embed', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 13. <object data>
    for tag in soup.find_all('object', data=True):
        links.add(normalize_url(base_url, tag['data']))

    # 14. <form action>
    for tag in soup.find_all('form', action=True):
        links.add(normalize_url(base_url, tag['action']))

    # 15. <meta refresh> content URL
    for tag in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
        if 'content' in tag.attrs:
            match = re.search(r'url=["\']?([^"\'>]+)', tag['content'], re.I)
            if match:
                links.add(normalize_url(base_url, match.group(1)))

    # 16. CSS url() in style attributes
    for tag in soup.find_all(style=True):
        urls = re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', tag['style'])
        for u in urls:
            links.add(normalize_url(base_url, u))

    # 17. CSS url() in <style> tags
    for tag in soup.find_all('style'):
        urls = re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', tag.string or '')
        for u in urls:
            links.add(normalize_url(base_url, u))

    # 18. @import in <style>
    for tag in soup.find_all('style'):
        imports = re.findall(r'@import\s+["\']([^"\']+)["\']', tag.string or '')
        for u in imports:
            links.add(normalize_url(base_url, u))

    # 19. <link rel="stylesheet" href>
    for tag in soup.find_all('link', rel=lambda x: x and 'stylesheet' in x, href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 20. <link rel="icon" href>
    for tag in soup.find_all('link', rel=lambda x: x and 'icon' in x, href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 21. <link rel="manifest" href>
    for tag in soup.find_all('link', rel='manifest', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 22. <link rel="preload" href>
    for tag in soup.find_all('link', rel='preload', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 23. <link rel="prefetch" href>
    for tag in soup.find_all('link', rel='prefetch', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 24. <link rel="dns-prefetch" href>
    for tag in soup.find_all('link', rel='dns-prefetch', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 25. <link rel="preconnect" href>
    for tag in soup.find_all('link', rel='preconnect', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 26. <meta property="og:image">
    for tag in soup.find_all('meta', property='og:image', content=True):
        links.add(normalize_url(base_url, tag['content']))

    # 27. <meta name="twitter:image">
    for tag in soup.find_all('meta', attrs={'name': 'twitter:image'}, content=True):
        links.add(normalize_url(base_url, tag['content']))

    # 28. JSON-LD @id / url
    for tag in soup.find_all('script', type='application/ld+json'):
        try:
            data = json.loads(tag.string or '')
            if isinstance(data, dict):
                for key in ['@id', 'url', 'image', 'logo']:
                    if key in data and isinstance(data[key], str):
                        links.add(normalize_url(base_url, data[key]))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and '@id' in item:
                        links.add(normalize_url(base_url, item['@id']))
        except:
            pass

    # 29. <link rel="amphtml">
    for tag in soup.find_all('link', rel='amphtml', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 30. <link rel="alternate" hreflang>
    for tag in soup.find_all('link', rel='alternate', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 31. <area href>
    for tag in soup.find_all('area', href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 32. <base href> (affects normalization)
    base_tag = soup.find('base', href=True)
    if base_tag:
        base_url = normalize_url('', base_tag['href'])

    # 33. <param value> in <object>
    for tag in soup.find_all('param', name='movie', value=True):
        links.add(normalize_url(base_url, tag['value']))

    # 34. <blockquote cite>
    for tag in soup.find_all('blockquote', cite=True):
        links.add(normalize_url(base_url, tag['cite']))

    # 35. <q cite>
    for tag in soup.find_all('q', cite=True):
        links.add(normalize_url(base_url, tag['cite']))

    # 36. <ins cite> / <del cite>
    for tag in soup.find_all(['ins', 'del'], cite=True):
        links.add(normalize_url(base_url, tag['cite']))

    # 37. <body background>
    if soup.body and soup.body.get('background'):
        links.add(normalize_url(base_url, soup.body['background']))

    # 38. <table background>
    for tag in soup.find_all('table', background=True):
        links.add(normalize_url(base_url, tag['background']))

    # 39. <td background>
    for tag in soup.find_all('td', background=True):
        links.add(normalize_url(base_url, tag['background']))

    # 40. <input src> (image inputs)
    for tag in soup.find_all('input', src=True):
        links.add(normalize_url(base_url, tag['src']))

    # 41. <button formaction>
    for tag in soup.find_all('button', formaction=True):
        links.add(normalize_url(base_url, tag['formaction']))

    # 42. <link rel="apple-touch-icon">
    for tag in soup.find_all('link', rel=lambda x: x and 'apple-touch-icon' in x, href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 43. <link rel="shortcut icon">
    for tag in soup.find_all('link', rel=lambda x: x and 'icon' in x.lower(), href=True):
        links.add(normalize_url(base_url, tag['href']))

    # 44. <svg><image xlink:href>
    for tag in soup.find_all('image', {'xlink:href': True}):
        links.add(normalize_url(base_url, tag['xlink:href']))

    # 45. <use xlink:href> in SVG
    for tag in soup.find_all('use', {'xlink:href': True}):
        href = tag['xlink:href']
        if href.startswith('#'):
            continue
        links.add(normalize_url(base_url, href))

    # 46. data-src attributes (lazyload)
    for tag in soup.find_all(lambda t: t.has_attr('data-src')):
        links.add(normalize_url(base_url, tag['data-src']))

    # 47. data-srcset
    for tag in soup.find_all(lambda t: t.has_attr('data-srcset')):
        for src in tag['data-srcset'].split(','):
            url = src.strip().split()[0]
            links.add(normalize_url(base_url, url))

    # 48. background-image in inline style
    for tag in soup.find_all(style=True):
        bg = re.findall(r'background-image\s*:\s*url\(["\']?([^"\'\)]+)["\']?\)', tag['style'])
        for u in bg:
            links.add(normalize_url(base_url, u))

    # 49. Web App Manifest icons
    for tag in soup.find_all('link', rel='manifest', href=True):
        manifest_url = normalize_url(base_url, tag['href'])
        links.add(manifest_url)
        try:
            resp = requests.get(manifest_url, timeout=5)
            if resp.ok:
                manifest = resp.json()
                for icon in manifest.get('icons', []):
                    if 'src' in icon:
                        links.add(normalize_url(manifest_url, icon['src']))
        except:
            pass

    # 50. Sitemap URLs from robots.txt
    try:
        robots_url = urljoin(base_url, '/robots.txt')
        resp = requests.get(robots_url, timeout=5)
        if resp.ok:
            for line in resp.text.splitlines():
                if line.lower().startswith('sitemap:'):
                    sitemap = line.split(':', 1)[1].strip()
                    links.add(sitemap)
    except:
        pass

    # Filter valid URLs
    return {u for u in links if is_valid_url(u, base_domain)}

def extract_links_from_css(css_content, base_url, base_domain):
    links = set()
    parsed = cssutils.parseString(css_content)
    for rule in parsed:
        if rule.type == rule.STYLE_RULE:
            for prop in rule.style:
                urls = re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', prop.value)
                for u in urls:
                    full = normalize_url(base_url, u)
                    if is_valid_url(full, base_domain):
                        links.add(full)
    return links

def extract_links_from_js(js_content, base_url, base_domain):
    links = set()
    patterns = [
        # 1. Standard quoted URLs
        r'["\'](https?://[^"\']+)["\']',
        r'=["\'](/[^"\']*?\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|otf|ico|webp|avif|mp4|webm|ogg|mp3|wav|json|xml|csv|pdf|zip|tar|gz|exe|apk|ipa|deb|rpm|bin|iso|dmg|pkg))["\']',
        
        # 2. fetch(), axios, XMLHttpRequest
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
        r'XMLHttpRequest.*?\.open\([^\)]*?["\']([^"\']+)["\']',
        r'request\(["\']([^"\']+)["\']',
        
        # 3. Dynamic string concatenation
        r'["\']([^"\']*?\.(js|css|json|xml|csv|pdf|png|jpg|gif|svg|mp4|mp3|woff2?|ttf|eot|otf|webp|avif))["\']\s*\+\s*["\']([^"\']+)["\']',
        r'[`\'"]([^`\'"]*?)/(api|auth|graphql|admin|login|logout|upload|download|data|assets|static|cdn|media|images|videos|files|config|env|backup|debug|test|dev|staging|prod)[^`\'"]*?)[`\'"]',
        
        # 4. Template literals (backticks)
        r'`([^`]*?https?://[^`]+?)`',
        r'`([^`]*?\.(js|css|png|jpg|svg|json|xml|pdf|mp4|mp3|woff2?|ttf|eot|otf|webp|avif))`',
        
        # 5. location / window.open / href assignments
        r'location\s*=\s*["\']([^"\']+)["\']',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
        r'window\.open\(["\']([^"\']+)["\']',
        r'href\s*=\s*["\']([^"\']+)["\']',
        r'src\s*=\s*["\']([^"\']+)["\']',
        r'data-src\s*=\s*["\']([^"\']+)["\']',
        
        # 6. WebSocket / Socket.IO
        r'new WebSocket\(["\']([^"\']+)["\']',
        r'io\(["\']([^"\']+)["\']',
        r'Socket\.?IO\(["\']([^"\']+)["\']',
        
        # 7. import / require / dynamic import
        r'import\s+.*?from\s+["\']([^"\']+)["\']',
        r'require\(["\']([^"\']+)["\']',
        r'import\(["\']([^"\']+)["\']',
        
        # 8. API endpoints (common paths)
        r'["\']/(v1|v2|api|auth|graphql|rest|admin|dashboard|login|logout|register|oauth|callback|webhook|upload|download|files|media|assets|static|cdn|images|videos|data|config|env|debug|test|health|status|metrics|ping|pong|version|info|about|contact|support|faq|docs|blog|shop|cart|checkout|payment|order|user|profile|settings|notifications|messages|chat|feed|timeline|search|results|sitemap|robots|manifest|sw|service-worker|worker|worker\.js)["\']',
        
        # 9. Cloud storage / CDN
        r'["\'](https?://[^"\']*?\.(s3\.amazonaws\.com|cloudfront\.net|storage\.googleapis\.com|firebasestorage\.googleapis\.com|github\.io|vercel\.app|netlify\.app|cloudflare\.com|bunnycdn\.com|fastly\.net|akamai\.net|digitaloceanspaces\.com|backblazeb2\.com|wasabisys\.com|r2\.cloudflarestorage\.com|supabase\.co|firebaseapp\.com|githubusercontent\.com|raw\.githubusercontent\.com))[^"\']*["\']',
        
        # 10. GraphQL / API payloads
        r'["\']query.*?["\']:\s*["\']([^"\']+)["\']',
        r'["\']mutation.*?["\']:\s*["\']([^"\']+)["\']',
        r'endpoint["\']\s*:\s*["\']([^"\']+)["\']',
        
        # 11. Environment / config
        r'process\.env\.([A-Z_]+)\s*\+\s*["\']([^"\']+)["\']',
        r'window\.config\.([a-zA-Z]+)\s*\+\s*["\']([^"\']+)["\']',
        r'__API_URL__\s*\+\s*["\']([^"\']+)["\']',
        
        # 12. Inline JSON URLs
        r'["\']url["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']endpoint["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']baseUrl["\']\s*:\s*["\']([^"\']+)["\']',
        
        # 13. React / Vue / Angular
        r'<link.*?href=["\']([^"\']+)["\']',
        r'<script.*?src=["\']([^"\']+)["\']',
        r'<img.*?src=["\']([^"\']+)["\']',
        r'srcSet=["\']([^"\']+)["\']',
        r'data-srcset=["\']([^"\']+)["\']',
        
        # 14. Background images in JS
        r'backgroundImage.*?url\(["\']([^"\']+)["\']',
        r'style.*?background.*?url\(["\']([^"\']+)["\']',
        
        # 15. File uploads / downloads
        r'["\']upload[^"\']*["\']',
        r'["\']download[^"\']*["\']',
        r'["\']export[^"\']*["\']',
        r'["\']import[^"\']*["\']',
        
        # 16. Analytics / Tracking
        r'gtag\(["\']config["\'].*?["\']([^"\']+)["\']',
        r'_gaq\.push.*?\["\']([^"\']+)["\']',
        r'analytics\.track.*?\(["\']([^"\']+)["\']',
        
        # 17. Maps / Geolocation
        r'google\.maps\.api.*?key=([^&]+)',
        r'maps\.googleapis\.com.*?key=([^&]+)',
        r'mapbox.*?access_token=([^&]+)',
        
        # 18. OAuth / Auth redirects
        r'["\']client_id["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']redirect_uri["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']response_type["\']\s*:\s*["\']([^"\']+)["\']',
        
        # 19. Webhooks / Callbacks
        r'["\']webhook["\']\s*:\s*["\']([^"\']+)["\']',
        r'["\']callback["\']\s*:\s*["\']([^"\']+)["\']',
        
        # 20. Service Workers / PWA
        r'register\(["\']([^"\']+\.js)["\']',
        r'navigator\.serviceWorker\.register\(["\']([^"\']+)["\']',
        
        # 21. iframe / embed
        r'<iframe.*?src=["\']([^"\']+)["\']',
        r'embed.*?src=["\']([^"\']+)["\']',
        
        # 22. JSONP / CORS
        r'jsonp=["\']([^"\']+)["\']',
        r'callback=["\']([^"\']+)["\']',
        
        # 23. Dynamic imports
        r'import\([^)]*?["\']([^"\']+)["\']',
        r'await import\(["\']([^"\']+)["\']',
        
        # 24. Worker scripts
        r'new Worker\(["\']([^"\']+)["\']',
        r'new SharedWorker\(["\']([^"\']+)["\']',
        
        # 25. Blob / Object URLs (partial)
        r'URL\.createObjectURL\([^)]*?["\']([^"\']+)["\']',
        
        # 26. Base64 data URLs (skip actual data)
        r'data:(image|video|audio|application)/[^;]+;base64,([A-Za-z0-9+/=]+)',
        
        # 27. Common API patterns
        r'["\']/@[^"\']*["\']',
        r'["\']/api/[^"\']*["\']',
        r'["\']/v[0-9]/[^"\']*["\']',
        r'["\']/graphql[^"\']*["\']',
        
        # 28. Admin / Debug panels
        r'["\']/(admin|dashboard|cpanel|wp-admin|phpmyadmin|webmail|login|auth|oauth|debug|test|dev|staging|backup|config|env|git|svn)["\']',
        
        # 29. File extensions (extended)
        r'\.([a-z0-9]{1,5})(?=[^\w]|$)',
        
        # 30. Full URLs in comments
        r'//.*?https?://[^\s]+',
        r'/\*[\s\S]*?\*/.*?https?://[^\s]+',
    ]
    for p in patterns:
        for m in re.findall(p, js_content, re.I):
            full = normalize_url(base_url, m)
            if is_valid_url(full, base_domain):
                links.add(full)
    return links

# === KEYWORD & API SEARCH ===
def search_keywords(content, url, keywords):
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        for kw in keywords:
            if re.search(kw, line, re.I):
                match = re.search(kw, line, re.I).group()
                ctx = "\n".join(lines[max(0,i-1):min(len(lines),i+2)])
                findings.append({'url': url, 'keyword': kw, 'line': i+1, 'match': match, 'context': ctx})
    return findings

def extract_api_keys(content, url):
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        for name, pat in API_KEY_PATTERNS.items():
            for m in re.finditer(pat, line):
                ctx = "\n".join(lines[max(0,i-1):min(len(lines),i+2)])
                findings.append({'url': url, 'type': name, 'match': m.group(), 'line': i+1, 'context': ctx})
    return findings

# === CRAWLER ===
def download_and_parse(url, session, base_domain, visited, depth, max_depth, extensions, keywords, extract_keys, screenshot_dir, stealth_delay):
    if depth > max_depth or url in visited:
        return set(), [], []
    visited.add(url)
    assets = set()
    kws = []
    apis = []

    time.sleep(random.uniform(stealth_delay[0], stealth_delay[1]))
    headers = get_random_headers()

    try:
        resp = session.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code != 200:
            return assets, kws, apis

        ctype = resp.headers.get('Content-Type', '').lower()
        ext = url.split('?')[0].split('#')[0].split('.')[-1].lower()
        content = resp.text

        if 'text/html' in ctype or ext == 'html':
            assets.update(extract_links_from_html(content, url, base_domain))
            if keywords:
                kws.extend(search_keywords(content, url, keywords))
            if extract_keys:
                apis.extend(extract_api_keys(content, url))
            if screenshot_dir:
                threading.Thread(target=take_screenshot, args=(url, screenshot_dir), daemon=True).start()

        elif 'text/css' in ctype or ext == 'css':
            assets.update(extract_links_from_css(content, url, base_domain))
            if keywords:
                kws.extend(search_keywords(content, url, keywords))
            if extract_keys:
                apis.extend(extract_api_keys(content, url))

        elif 'javascript' in ctype or ext in ('js', 'mjs'):
            assets.update(extract_links_from_js(content, url, base_domain))
            if keywords:
                kws.extend(search_keywords(content, url, keywords))
            if extract_keys:
                apis.extend(extract_api_keys(content, url))

        elif ext in (extensions or []) or any(x in ctype for x in ['image/', 'font/']):
            assets.add(url)

        if 'text/html' in ctype and depth < max_depth:
            for link in extract_links_from_html(content, url, base_domain):
                if link not in visited:
                    a, kw, ap = download_and_parse(link, session, base_domain, visited, depth+1, max_depth, extensions, keywords, extract_keys, screenshot_dir, stealth_delay)
                    assets.update(a)
                    kws.extend(kw)
                    apis.extend(ap)

    except Exception as e:
        print(f"{Fore.RED}[!] Error fetching {url}: {e}", file=sys.stderr)

    return assets, kws, apis

# === MAIN CRAWL ===
def crawl(target_url, output_file=None, extensions=None, depth=MAX_DEPTH, keywords=None, extract_keys=False, screenshot_dir=None, stealth_delay=(DELAY_MIN, DELAY_MAX), subdomains_brute=False, wordlist_file=None):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    parsed = urlparse(target_url)
    base_domain = parsed.netloc

    sub_urls = []
    if subdomains_brute:
        print(f"{Fore.CYAN}[+] Brute-forcing subdomains for {base_domain}...")
        wl = SUBDOMAIN_WORDLIST
        if wordlist_file and os.path.exists(wordlist_file):
            with open(wordlist_file) as f:
                wl = [l.strip() for l in f if l.strip()]
        sub_urls = brute_force_subdomains(base_domain, wl)
        print(f"{Fore.GREEN}[+] Found {len(sub_urls)} valid subdomains")

    session = requests.Session()
    visited = set()
    all_assets = set()
    all_kws = []
    all_apis = []

    print(f"{Fore.CYAN}[+] Starting recon on: {target_url}")
    print(f"{Fore.CYAN}[+] Domain: {base_domain} | Depth: {depth} | Stealth: {stealth_delay[0]}-{stealth_delay[1]}s")
    if keywords:
        print(f"{Fore.YELLOW}[+] Hunting {len(keywords)} keywords...")
    if extract_keys:
        print(f"{Fore.YELLOW}[+] Extracting API keys...")
    if screenshot_dir:
        print(f"{Fore.YELLOW}[+] Screenshots → {screenshot_dir}")
    for sub in sub_urls:
        print(f"{Fore.GREEN}[+] Subdomain: {sub}")

    urls_to_crawl = [target_url] + sub_urls
    for start_url in urls_to_crawl:
        a, kw, ap = download_and_parse(start_url, session, base_domain, visited, 0, depth, extensions, keywords or [], extract_keys, screenshot_dir, stealth_delay)
        all_assets.update(a)
        all_kws.extend(kw)
        all_apis.extend(ap)

    if extensions:
        all_assets = {a for a in all_assets if any(a.lower().endswith('.' + e.lower()) for e in extensions)}

    unique_assets = sorted(all_assets)

    # Output
    print(f"\n{Fore.GREEN}[+] Found {len(unique_assets)} unique assets:\n")
    for asset in unique_assets:
        print(f"{Fore.WHITE}{asset}")
    if output_file:
        with open(output_file, 'w') as f:
            for a in unique_assets:
                f.write(a + '\n')
        print(f"\n{Fore.GREEN}[+] Saved to {output_file}")

    # Keyword findings
    if all_kws:
        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED} KEYWORD FINDINGS ({len(all_kws)})")
        print(f"{Fore.RED}{'='*60}")
        for f in all_kws:
            print(f"{Fore.YELLOW}URL: {f['url']}")
            print(f"{Fore.MAGENTA}Keyword: {f['keyword']} | Line {f['line']} | Match: {f['match']}")
            print(f"{Fore.CYAN}Context:\n{f['context']}\n{Fore.RED}{'-'*50}")

    # API keys
    if all_apis:
        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED} POTENTIAL API KEYS ({len(all_apis)})")
        print(f"{Fore.RED}{'='*60}")
        for f in all_apis:
            print(f"{Fore.YELLOW}URL: {f['url']}")
            print(f"{Fore.MAGENTA}Type: {f['type']} | Line {f['line']} | Key: {f['match']}")
            print(f"{Fore.CYAN}Context:\n{f['context']}\n{Fore.RED}{'-'*50}")
    else:
        print(f"\n{Fore.GREEN}[+] No API keys found.")

    return unique_assets, base_domain, all_kws, all_apis

# === AI REPORT ===
def generate_recon_report(assets, domain, kws, apis):
    prompt = f"""
Senior pentester recon summary:
- Target: {domain}
- Assets: {len(assets)}
- Keywords: {len(kws)}
- API Keys: {len(apis)}
Sample assets: {', '.join(list(assets)[:5])}
Key findings: {', '.join([f['match'] for f in apis[:3]]) if apis else 'None'}
Next steps?
"""
    try:
        print(f"\n{Fore.CYAN}[+] Generating AI report...")
        r = requests.post("https://text.pollinations.ai/openai/openai", json={"prompt": prompt, "model": "gpt-4o"}, timeout=60)
        if r.status_code == 200:
            report = r.text.strip()
            print(f"\n{Fore.GREEN}{'='*60}\nAI RECON REPORT\n{'='*60}\n{report}\n{'='*60}")
    except Exception as e:
        print(f"{Fore.RED}[!] AI failed: {e}")

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("-o", "--output")
    parser.add_argument("-e", "--ext", nargs="+")
    parser.add_argument("-d", "--depth", type=int, default=MAX_DEPTH)
    parser.add_argument("-k", "--keywords", nargs="+")
    parser.add_argument("--extract-keys", action="store_true")
    parser.add_argument("--screenshots")
    parser.add_argument("--stealth", nargs=2, type=float, default=(DELAY_MIN, DELAY_MAX))
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--wordlist")
    parser.add_argument("--no-ai", action="store_true")
    args = parser.parse_args()

    keywords = args.keywords or DEFAULT_KEYWORDS
    screenshot_dir = args.screenshots or ('shots' if '--screenshots' in sys.argv else None)

    assets, domain, kws, apis = crawl(
        args.url, args.output, args.ext, args.depth, keywords, args.extract_keys,
        screenshot_dir, tuple(args.stealth), args.subdomains, args.wordlist
    )

    if not args.no_ai:
        generate_recon_report(assets, domain, kws, apis)