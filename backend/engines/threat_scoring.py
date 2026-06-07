import logging

logger = logging.getLogger(__name__)

def calculate_score(event, factors):
    """
    Calculate threat score based on factors list.
    factors = [{'name': 'Encoded PowerShell', 'score': 30}]
    """
    total_score = sum(f.get('score', 0) for f in factors)
    
    if total_score >= 76:
        severity = "critical"
    elif total_score >= 51:
        severity = "high"
    elif total_score >= 26:
        severity = "medium"
    else:
        severity = "low"
        
    return total_score, severity

async def start_scoring_engine():
    logger.info("Starting Threat Scoring Engine...")
    # Typically this listens to correlator or alerts.
    # In this simplified arch, detections call calculate_score directly.
    import asyncio
    try:
        while True:
            await asyncio.sleep(60)
    except asyncio.CancelledError:
        pass
