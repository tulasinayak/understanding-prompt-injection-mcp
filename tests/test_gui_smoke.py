"""The GUI script renders without exceptions (no model run is started)."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "gui" / "app.py")


def test_gui_renders():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception, [e.value for e in at.exception]
    assert [t.label for t in at.tabs] == ["Run an attack", "New test", "Results"]
    scenario_box = at.selectbox[0]
    assert any("exfil-plain-payroll" in o for o in scenario_box.options)
    assert any(b.label == "Run" for b in at.button)


def test_gui_by_hand_mode_renders():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.selectbox[0].select("(write one by hand)").run()
    assert not at.exception, [e.value for e in at.exception]
    assert any(t.label == "Injected text (payload)" for t in at.text_area)
