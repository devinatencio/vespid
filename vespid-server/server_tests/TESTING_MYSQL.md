# MySQL Test Database Setup

This project runs property-based and integration tests against both SQLite (in-memory) and MySQL backends. MySQL tests are automatically skipped when the database is unavailable.

## Expected Configuration

The test suite expects the following MySQL credentials (defined in `conftest.py`):

| Setting  | Value            |
|----------|------------------|
| Host     | `localhost`      |
| Port     | `3306`           |
| Database | `vespid_test` |
| User     | `vespid_test` |
| Password | `test_password`  |

## Local Development (Docker Compose)

Add this service to your `docker-compose.yml`:

```yaml
services:
  mysql-test:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: ""
      MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
      MYSQL_DATABASE: vespid_test
      MYSQL_USER: vespid_test
      MYSQL_PASSWORD: test_password
    ports:
      - "3306:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 3s
      retries: 10
```

Start it with:

```bash
docker compose up -d mysql-test
```

Wait for the health check to pass, then run tests:

```bash
.venv/bin/python -m pytest vespid-server/tests/ -v
```

MySQL-parameterized tests will run automatically when the database is reachable. If MySQL is unavailable, those test variants are skipped with a clear message.

## GitHub Actions CI

Add a MySQL service container to your workflow:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest

    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: ""
          MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
          MYSQL_DATABASE: vespid_test
          MYSQL_USER: vespid_test
          MYSQL_PASSWORD: test_password
        ports:
          - 3306:3306
        options: >-
          --health-cmd="mysqladmin ping -h localhost"
          --health-interval=5s
          --health-timeout=3s
          --health-retries=10

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run tests
        run: python -m pytest vespid-server/tests/ -v
```

The `conftest.py` fixture automatically detects MySQL availability at import time. No environment variables or extra configuration are needed beyond having the service running with the credentials above.

## How It Works

- `conftest.py` defines an `intel_db` fixture parameterized over `["sqlite", "mysql"]`.
- At import time, it attempts to connect to MySQL. If unreachable, MySQL variants are marked `skipif`.
- If the test database doesn't exist but the server is reachable, `conftest.py` attempts to create it using root access (empty password).
- Each test gets a clean slate: data is deleted before and after each MySQL test run.
