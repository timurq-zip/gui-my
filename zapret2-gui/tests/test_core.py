from pathlib import Path
from zapret2_gui.models import AppState, Profile, Step, GameFilter, Blob
from zapret2_gui.cli_builder import build_state_args, build_args, intercept_ports, active_profiles, merge_ports
from zapret2_gui.validator import validate_args, validate_desync, has_errors
from zapret2_gui.nft import build_ruleset
from zapret2_gui.scanners.strategies import merge_defaults, GENERATORS
import zapret2_gui.cli_builder as cb


def mk_state(tmp_path, monkeypatch):
    lua = tmp_path / "lua"
    lua.mkdir()
    for f in cb.DEFAULT_LUA:
        (lua / f).write_text("function fake() end")
    st = AppState()
    st.settings.zapret2_dir = str(tmp_path)
    return st


def test_profile_cli(tmp_path, monkeypatch):
    st = mk_state(tmp_path, monkeypatch)
    st.profiles.append(Profile(name="a", filter_tcp="443", filter_l7=["tls"], steps=[
        Step("fake", [["blob", "fake_default_tls"], ["tcp_md5", ""], ["repeats", "6"]], payload="tls_client_hello", out_range="-d10"),
        Step("multidisorder", [["pos", "1,midsld"]])]))
    a = build_state_args(st)
    assert "--filter-tcp=443" in a and "--filter-l7=tls" in a
    i = a.index("--out-range=-d10")
    assert a[i + 1] == "--payload=tls_client_hello"
    assert a[i + 2] == "--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=6"
    assert a[-1] == "--lua-desync=multidisorder:pos=1,midsld"
    assert not has_errors(validate_args(a))


def test_two_profiles_new(tmp_path, monkeypatch):
    st = mk_state(tmp_path, monkeypatch)
    for p in ("80", "443"):
        st.profiles.append(Profile(filter_tcp=p, steps=[Step("multisplit", [["pos", "2"]])]))
    assert build_state_args(st).count("--new") == 1


def test_gamefilter(tmp_path, monkeypatch):
    st = mk_state(tmp_path, monkeypatch)
    st.game = GameFilter(enabled=True, ports="27015-27030,3074")
    st.mode = "both"
    a = build_state_args(st)
    assert "--filter-udp=27015-27030,3074" in a
    assert any(x.startswith("--lua-desync=fake:blob=0x" + "00" * 16 + ":repeats=2") for x in a)
    assert not has_errors(validate_args(a))
    st.mode = "tcp"
    assert not any("GameFilter" in p.name for p in active_profiles(st))


def test_mode_filters(tmp_path, monkeypatch):
    st = mk_state(tmp_path, monkeypatch)
    st.profiles = [Profile(name="t", filter_tcp="443", steps=[Step("drop")]), Profile(name="u", filter_udp="443", steps=[Step("drop")])]
    st.mode = "tcp"
    assert [p.name for p in active_profiles(st)] == ["t"]
    st.mode = "udp"
    assert [p.name for p in active_profiles(st)] == ["u"]
    assert intercept_ports(active_profiles(st)) == ("", "443")


def test_validator_errors():
    bad = ["--qnum=200", "--filter-tcp=99999", "--out-range=zz", "--lua-desync=fake:blob=0xABC:repeats=0",
           "--lua-desync=multisplit:pos=a/b", "--lua-desync=fake:blob=nonexistent"]
    msgs = [str(i) for i in validate_args(bad) if i.level == "error"]
    assert len(msgs) >= 5


def test_validator_good_desync():
    ok = validate_desync("fake:blob=0x00000000:repeats=2:ip_autottl=-2,3-20", set(), set())
    assert not has_errors(ok)
    assert has_errors(validate_desync("fake:ip_autottl=bad", set(), set()))
    assert any(i.level == "warn" for i in validate_desync("fakee:x=1", set(), set()))


def test_custom_blob_defined():
    args = ["--blob=myb:0x0102", "--lua-desync=fake:blob=myb"]
    assert not has_errors(validate_args(args))


def test_nft():
    s = build_ruleset("80,443", "19294-19344", 200, 12, True, "", ["1.2.3.4", "2001:db8::1"])
    assert "queue num 200 bypass" in s and "19294-19344" in s
    assert "ip daddr { 1.2.3.4 }" in s and "ip6 daddr { 2001:db8::1 }" in s
    assert "notrack" in s and "0x40000000" in s
    try:
        build_ruleset("", "", 200)
        assert False
    except ValueError:
        pass


def test_scanners_generate():
    for sc in ("udp", "game", "discord"):
        cfg = merge_defaults({"scanner": sc, "target": {"host": "x", "ports": "27015-27030", "port": 443}})
        c = GENERATORS[sc](cfg)
        assert c and all(x.profile.steps for x in c)
    d = GENERATORS["discord"](merge_defaults({"scanner": "discord", "target": {"host": "x"}}))
    assert all(x.meta["repeats"] >= 6 for x in d)


def test_merge_ports():
    assert merge_ports("80,443", "443, 8080") == "80,443,8080"
