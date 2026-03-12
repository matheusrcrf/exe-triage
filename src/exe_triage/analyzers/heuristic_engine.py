import re

from exe_triage.models import AnalysisResult, HeuristicFinding, RiskScore
from exe_triage.rules.heuristic_rules import (
    HEURISTIC_RULES,
    RECOMMENDATIONS_BY_CATEGORY,
    WEAK_CONTEXT_CAP,
)


def score(result: AnalysisResult) -> None:
    """Evaluate heuristic rules, compute risk score and generate recommendations."""
    findings: list[HeuristicFinding] = []
    breakdown: dict[str, int] = {}
    weak_context_total = 0

    # Build lookup structures
    all_strings_lower = [s.lower() for s in _collect_all_strings(result)]
    all_imports_flat = {
        func.lower()
        for funcs in result.pe_info.imports.values()
        for func in funcs
    }
    # Also keep original case for display
    import_func_to_dll: dict[str, str] = {}
    for dll, funcs in result.pe_info.imports.items():
        for func in funcs:
            import_func_to_dll[func.lower()] = f"{func} in {dll}"

    for rule in HEURISTIC_RULES:
        matched = False
        evidence = ""

        if rule.source == "imports":
            signal_lower = (rule.signal or "").lower()
            for func_lower, display in import_func_to_dll.items():
                if signal_lower in func_lower:
                    matched = True
                    evidence = display
                    break

        elif rule.source == "strings":
            if rule.signal_regex:
                pattern = re.compile(rule.signal_regex, re.IGNORECASE)
                for s in _collect_all_strings(result):
                    if pattern.search(s):
                        matched = True
                        evidence = s[:150]
                        break
            elif rule.signal:
                signal_lower = rule.signal.lower()
                for s_lower in all_strings_lower:
                    if signal_lower in s_lower:
                        matched = True
                        evidence = rule.signal
                        break

        elif rule.source == "signature":
            if rule.id == "WEAK_UNSIGNED" and not result.signature.signed:
                matched = True
                evidence = "Executável sem assinatura digital"

        elif rule.source == "iocs":
            if rule.id == "WEAK_MULTIPLE_URLS" and len(result.iocs.urls) > 3:
                matched = True
                evidence = f"{len(result.iocs.urls)} URLs detectadas"

        if matched:
            findings.append(
                HeuristicFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    description=rule.description,
                    weight=rule.weight,
                    evidence=evidence,
                )
            )
            breakdown[rule.category] = breakdown.get(rule.category, 0) + rule.weight
            if rule.category == "weak_context":
                weak_context_total += rule.weight

    # Apply weak context cap
    weak_context_capped = min(weak_context_total, WEAK_CONTEXT_CAP)
    score_total = sum(breakdown.values()) - weak_context_total + weak_context_capped
    # Update breakdown to reflect cap
    if weak_context_total > 0:
        breakdown["weak_context"] = weak_context_capped

    # Determine level
    level = _classify_score(score_total)

    # Apply elevation rules
    active_categories = {f.category for f in findings}

    if "process_injection" in active_categories:
        if level in ("baixo", "médio"):
            level = "alto"

    if "obfuscation" in active_categories and "remote_download" in active_categories:
        if level in ("baixo", "médio"):
            level = "alto"

    result.findings = findings
    result.risk_score = RiskScore(total=score_total, level=level, breakdown=breakdown)
    result.recommendations = _generate_recommendations(active_categories, level)


def _classify_score(score: int) -> str:
    if score >= 80:
        return "crítico"
    elif score >= 45:
        return "alto"
    elif score >= 20:
        return "médio"
    else:
        return "baixo"


def _collect_all_strings(result: AnalysisResult) -> list[str]:
    """Collect strings from IOCs and indicators for heuristic matching."""
    strings = []
    # Add IOC values
    strings.extend(result.iocs.urls)
    strings.extend(result.iocs.domains)
    strings.extend(result.iocs.file_paths)
    strings.extend(result.iocs.registry_keys)
    strings.extend(result.iocs.process_names)
    # Add indicator values
    strings.extend(ind.value for ind in result.indicators)
    return strings


def _generate_recommendations(active_categories: set[str], level: str) -> list[str]:
    recommendations = []
    priority_order = [
        "process_injection",
        "remote_download",
        "obfuscation",
        "persistence",
        "suspicious_automation",
        "suspicious_context",
        "weak_context",
    ]
    for cat in priority_order:
        if cat in active_categories:
            recommendations.append(RECOMMENDATIONS_BY_CATEGORY[cat])

    if level == "crítico":
        recommendations.append("Não executar. Analisar em ambiente isolado.")
    elif level == "alto":
        recommendations.append("Execução de alto risco. Analisar em ambiente controlado antes de executar.")

    return recommendations
