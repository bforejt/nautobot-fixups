"""Minimal Nautobot settings for the opt-in end-to-end test (disposable Postgres + Redis in Docker).

Used as DJANGO_SETTINGS_MODULE by tests/test_job_e2e.py and by tests/e2e/run_e2e.sh.
"""

import os

from nautobot.core.settings import *  # noqa: F403

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PG_PORT = os.environ.get("NB_E2E_PG_PORT", "55432")
REDIS_PORT = os.environ.get("NB_E2E_REDIS_PORT", "56379")

ALLOWED_HOSTS = ["*"]
SECRET_KEY = "e2e-only-not-a-real-secret"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "nautobot",
        "USER": "nautobot",
        "PASSWORD": "nautobot",
        "HOST": "127.0.0.1",
        "PORT": PG_PORT,
        "CONN_MAX_AGE": 300,
    }
}
DATABASES["job_logs"] = dict(DATABASES["default"], TEST={"MIRROR": "default"})
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://127.0.0.1:{REDIS_PORT}/1",
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
    }
}
CELERY_BROKER_URL = f"redis://127.0.0.1:{REDIS_PORT}/0"
# keep Nautobot's own result backend (NautobotDatabaseBackend) so self.fail() lands as FAILURE + result
CELERY_TASK_ALWAYS_EAGER = True  # run jobs inline in the test process
JOBS_ROOT = REPO_ROOT  # the repo's ``jobs`` package is imported as a top-level ``jobs`` module
GIT_ROOT = os.path.join(os.environ.get("NAUTOBOT_ROOT", "/tmp"), "git")
