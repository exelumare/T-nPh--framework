"""Tier 1 Verification Tests."""
import sys
import io
from unittest.mock import patch
from network.config import HTTPConfig, EvasionLevel
from network.client import HTTPClient
from core.context import TargetContext
from core.engine import AutoAssessmentEngine
from modules.sqli import SQLInjectionModule

# Mock isatty biar engine nggak nunggu input() di state EXPLOIT
@patch('sys.stdin')
def test_dedupe_single_param(mock_stdin, mock_server):
    """Test #13: 1 param vuln -> 1 finding, bukan 3."""
    mock_stdin.isatty.return_value = False # Biar auto-skip exploit
    
    config = HTTPConfig(random_seed=42, evasion_level=EvasionLevel.STANDARD, delay=0)
    client = HTTPClient(config)
    ctx = TargetContext()
    ctx.target.base_url = f"{mock_server}/sqli-error?q=1"
    ctx.http_client = client
    
    engine = AutoAssessmentEngine(ctx, [SQLInjectionModule()])
    engine.run()
    
    assert len(ctx.results.validated) == 1, f"Expected 1 finding, got {len(ctx.results.validated)}"
    assert ctx.results.validated[0].parameter == "q"
    client.close()

@patch('sys.stdin')
def test_footer_mysql_not_flagged(mock_stdin, mock_server):
    """Test #14: Payload reflected + footer 'MySQL' -> TIDAK boleh VALIDATED."""
    mock_stdin.isatty.return_value = False
    
    config = HTTPConfig(random_seed=42, evasion_level=EvasionLevel.NONE, delay=0)
    client = HTTPClient(config)
    ctx = TargetContext()
    ctx.target.base_url = f"{mock_server}/footer-mysql?q=1"
    ctx.http_client = client
    
    engine = AutoAssessmentEngine(ctx, [SQLInjectionModule()])
    engine.run()
    
    assert len(ctx.results.validated) == 0, f"Expected 0 finding, got {len(ctx.results.validated)}"
    client.close()

def test_seed_reproducibility():
    """Test #15: Same seed = same mutation."""
    config1 = HTTPConfig(random_seed=42, evasion_level=EvasionLevel.STANDARD, delay=0)
    config2 = HTTPConfig(random_seed=42, evasion_level=EvasionLevel.STANDARD, delay=0)
    
    c1 = HTTPClient(config1)
    c2 = HTTPClient(config2)
    
    url = "http://x/?q=SELECT UNION"
    mut1 = c1.mutator.mutate_url_parameters(url, "q")
    mut2 = c2.mutator.mutate_url_parameters(url, "q")
    
    assert mut1 == mut2, f"Expected same mutation, got {mut1} != {mut2}"
    c1.close()
    c2.close()
