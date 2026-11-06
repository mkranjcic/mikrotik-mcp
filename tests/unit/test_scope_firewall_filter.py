"""Unit tests for the IPv4 firewall filter scope."""

import asyncio

from tests.conftest import FakeExecutor


def _run(coro):
    return asyncio.run(coro)


def test_enable_disable_delegates_to_update_implementation(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_enable_filter_rule(ctx, rule_id="*1"))
    assert any("/ip firewall filter set *1" in c and "disabled=no" in c for c in fake.commands)

    fake.commands.clear()
    _run(m.mikrotik_disable_filter_rule(ctx, rule_id="*1"))
    assert any("/ip firewall filter set *1" in c and "disabled=yes" in c for c in fake.commands)


def test_update_filter_rule_direct(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_update_filter_rule(ctx, rule_id="*1", comment="test-rule"))
    assert any('/ip firewall filter set *1' in c and 'comment="test-rule"' in c for c in fake.commands)


def test_create_jump_carries_target(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_create_filter_rule(ctx, chain="forward", action="jump", jump_target="probe-chain"))
    assert any('action=jump jump-target="probe-chain"' in c for c in fake.commands)


def test_create_jump_requires_target(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    res = _run(m.mikrotik_create_filter_rule(ctx, chain="forward", action="jump"))
    assert "jump_target is required" in res
    assert not fake.commands


def test_create_jump_target_invalid_chars(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    res = _run(m.mikrotik_create_filter_rule(ctx, chain="forward", action="jump", jump_target='target"inject'))
    assert "contains invalid characters" in res
    assert not fake.commands


def test_update_jump_target(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_update_filter_rule(ctx, rule_id="*1", action="jump", jump_target="my-target"))
    assert any('/ip firewall filter set *1' in c and 'jump-target="my-target"' in c for c in fake.commands)


def test_create_reject_carries_reject_with(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_create_filter_rule(ctx, chain="forward", action="reject", reject_with="icmp-admin-prohibited"))
    assert any("action=reject reject-with=icmp-admin-prohibited" in c for c in fake.commands)


def test_create_reject_invalid_chars(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    res = _run(m.mikrotik_create_filter_rule(ctx, chain="forward", action="reject", reject_with='icmp"inject'))
    assert "contains invalid characters" in res
    assert not fake.commands


def test_update_reject_with(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_update_filter_rule(ctx, rule_id="*1", action="reject", reject_with="tcp-reset"))
    assert any("/ip firewall filter set *1" in c and "reject-with=tcp-reset" in c for c in fake.commands)


def test_update_reject_with_clear(ctx, monkeypatch):
    from mcp_mikrotik.scope import firewall_filter as m

    fake = FakeExecutor()
    monkeypatch.setattr(m, "execute_mikrotik_command", fake, raising=True)

    _run(m.mikrotik_update_filter_rule(ctx, rule_id="*1", reject_with=""))
    assert any("/ip firewall filter set *1" in c and "!reject-with" in c for c in fake.commands)
