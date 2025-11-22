from streamlit.testing import AppTest

def test_app_renders_without_error():
    """Basic smoke test: app runs and produces some HTML."""
    at = AppTest.from_file("app.py").run()
    # should have rendered some HTML
    assert len(at.html) > 0


def test_no_escaped_div_in_answers():
    """Check that we are not showing &lt;div in rendered HTML."""
    at = AppTest.from_file("app.py").run()

    # raw html of the rendered app
    html = at.html

    # We expect to see our CSS class, but not as escaped text.
    assert "&lt;div class='answer-text'" not in html
    assert "&lt;div class=\"answer-text\"" not in html