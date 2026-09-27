"""Tests for the vespid_server.py CLI entry point."""

import json
import sys
from unittest import mock

import pytest

# Import after path setup — the entry point lives at the package root
from vespid_server import build_parser, cmd_create_admin, cmd_init_db, main


class TestBuildParser:
    """Test that the argument parser is constructed correctly."""

    def test_parser_accepts_no_args(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None
        assert args.config is None

    def test_parser_accepts_config_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "/etc/vespid/config.json"])
        assert args.config == "/etc/vespid/config.json"

    def test_parser_accepts_init_db(self):
        parser = build_parser()
        args = parser.parse_args(["init-db"])
        assert args.command == "init-db"

    def test_parser_accepts_create_admin(self):
        parser = build_parser()
        args = parser.parse_args(["create-admin"])
        assert args.command == "create-admin"

    def test_parser_config_with_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "my.json", "init-db"])
        assert args.config == "my.json"
        assert args.command == "init-db"


class TestCmdInitDb:
    """Test the init-db command."""

    def test_calls_init_db_with_db_path(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "init-db"])

        with mock.patch("vespid_server.init_db") as mock_init:
            cmd_init_db(args)
            mock_init.assert_called_once_with(db_path)

    def test_prints_success_message(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "init-db"])

        with mock.patch("vespid_server.init_db"):
            cmd_init_db(args)

        captured = capsys.readouterr()
        assert "Initializing SQLite database at:" in captured.out
        assert db_path in captured.out
        assert "successfully" in captured.out


class TestCmdCreateAdmin:
    """Test the create-admin command."""

    def test_calls_create_user_with_admin_role(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "create-admin"])

        mock_conn = mock.MagicMock()
        with (
            mock.patch("builtins.input", return_value="myadmin"),
            mock.patch("vespid_server.getpass.getpass", side_effect=["secret123", "secret123"]),
            mock.patch("vespid_server.get_db", return_value=mock_conn) as mock_get_db,
            mock.patch("vespid_server.create_user") as mock_create,
        ):
            cmd_create_admin(args)
            mock_get_db.assert_called_once_with(db_path)
            mock_create.assert_called_once_with(mock_conn, "myadmin", "secret123", "admin")
            mock_conn.close.assert_called_once()

    def test_prints_success_message(self, tmp_path, capsys):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "create-admin"])

        mock_conn = mock.MagicMock()
        with (
            mock.patch("builtins.input", return_value="myadmin"),
            mock.patch("vespid_server.getpass.getpass", side_effect=["pass1", "pass1"]),
            mock.patch("vespid_server.get_db", return_value=mock_conn),
            mock.patch("vespid_server.create_user"),
        ):
            cmd_create_admin(args)

        captured = capsys.readouterr()
        assert "myadmin" in captured.out
        assert "successfully" in captured.out

    def test_exits_on_empty_username(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "create-admin"])

        with (
            mock.patch("builtins.input", return_value=""),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_create_admin(args)

        assert exc_info.value.code == 1

    def test_exits_on_empty_password(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "create-admin"])

        with (
            mock.patch("builtins.input", return_value="admin"),
            mock.patch("vespid_server.getpass.getpass", return_value=""),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_create_admin(args)

        assert exc_info.value.code == 1

    def test_exits_on_password_mismatch(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        parser = build_parser()
        args = parser.parse_args(["--config", str(config_file), "create-admin"])

        with (
            mock.patch("builtins.input", return_value="admin"),
            mock.patch("vespid_server.getpass.getpass", side_effect=["pass1", "pass2"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_create_admin(args)

        assert exc_info.value.code == 1


class TestMainDispatch:
    """Test that main() dispatches to the correct command handler."""

    def test_dispatches_init_db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        with mock.patch("vespid_server.init_db") as mock_init:
            main(["--config", str(config_file), "init-db"])
            mock_init.assert_called_once_with(db_path)

    def test_dispatches_create_admin(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))


        mock_conn = mock.MagicMock()
        with (
            mock.patch("builtins.input", return_value="admin"),
            mock.patch("vespid_server.getpass.getpass", side_effect=["pw", "pw"]),
            mock.patch("vespid_server.get_db", return_value=mock_conn),
            mock.patch("vespid_server.create_user") as mock_create,
        ):
            main(["--config", str(config_file), "create-admin"])
            mock_create.assert_called_once_with(mock_conn, "admin", "pw", "admin")

    def test_dispatches_run_server_when_no_command(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))

        with mock.patch("vespid_server.create_app") as mock_create_app:
            mock_app = mock.MagicMock()
            mock_app.config = {"HOST": "127.0.0.1", "PORT": 5000, "DEBUG": True}
            mock_create_app.return_value = mock_app

            main(["--config", str(config_file)])

            mock_create_app.assert_called_once_with(str(config_file))
            mock_app.run.assert_called_once_with(host="127.0.0.1", port=5000, debug=True)
