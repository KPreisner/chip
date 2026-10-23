import pytest

from chip import verify
from chip.cli import main

FAST = ["--bits", "16", "--max", "2000"]


def test_hash_prints_a_verifiable_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hash", "hunter2", *FAST]) == 0
    stored = capsys.readouterr().out.strip()
    assert stored.startswith("$chip$h=sha256,b=16,c=5,min=0,max=2000$")
    assert verify("hunter2", stored)


def test_hash_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hash", "pw", "-b", "12", "-c", "3", "--max", "500", "--hash", "md5"]) == 0
    assert "$chip$h=md5,b=12,c=3,min=0,max=500$" in capsys.readouterr().out


def test_verify_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    main(["hash", "hunter2", *FAST])
    stored = capsys.readouterr().out.strip()

    assert main(["verify", stored, "hunter2"]) == 0
    assert capsys.readouterr().out.strip() == "match"

    assert main(["verify", stored, "hunter3"]) == 1
    assert capsys.readouterr().out.strip() == "no match"


def test_password_is_prompted_for_when_omitted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda prompt: "hunter2")
    assert main(["hash", *FAST]) == 0
    assert verify("hunter2", capsys.readouterr().out.strip())


def test_hash_prompt_must_be_confirmed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["hunter2", "hunter3"])
    monkeypatch.setattr("getpass.getpass", lambda prompt: next(answers))
    assert main(["hash", *FAST]) == 2
    assert "passwords do not match" in capsys.readouterr().err


def test_closed_stdin_at_prompt_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def closed(prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("getpass.getpass", closed)
    assert main(["hash", *FAST]) == 2
    assert "no password given" in capsys.readouterr().err


def test_ctrl_c_at_prompt_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("getpass.getpass", interrupted)
    assert main(["verify", "$chip$anything"]) == 130


def test_unreachable_bounds_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    # 5 collisions among 65,536 values in exactly 10 iterations: every salt is rejected.
    assert main(["hash", "pw", "-b", "16", "--min", "10", "--max", "10"]) == 2
    assert "no salt met the iteration bounds" in capsys.readouterr().err


def test_invalid_parameters_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hash", "pw", "--bits", "99"]) == 2
    assert "bits must be in" in capsys.readouterr().err


def test_malformed_hash_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", "not-a-hash", "pw"]) == 2
    assert "not a valid CHIP hash string" in capsys.readouterr().err


def test_unknown_hash_rejected_by_argparse() -> None:
    with pytest.raises(SystemExit):
        main(["hash", "pw", "--hash", "crc32"])


def test_verbose_logs_attempts_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    # b = 12, C = 5 averages about 200 iterations, so max = 200 forces some retries.
    assert main(["hash", "pw", "-b", "12", "--max", "200", "-v"]) == 0
    captured = capsys.readouterr()
    assert "attempt 1: salt " in captured.err
    assert "collision 1 at iteration" in captured.err
    assert "accepted:" in captured.err
    assert " ms  " in captured.err  # elapsed-time column
    # stdout carries only the hash, so HASH=$(chip hash ... -v) still works.
    assert captured.out.count("\n") == 1
    assert verify("pw", captured.out.strip())


def test_quiet_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hash", "pw", *FAST]) == 0
    assert capsys.readouterr().err == ""
