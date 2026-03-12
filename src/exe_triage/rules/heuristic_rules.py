from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class HeuristicRule:
    id: str
    category: str
    weight: int
    description: str
    signal: str | None = None
    signal_regex: str | None = None
    source: str = "strings"


HEURISTIC_RULES: list[HeuristicRule] = [
    # -- SINAIS FORTES -------------------------------------------------------

    # Process Injection
    HeuristicRule(
        id="INJ_CREATEREMOTETHREAD",
        signal="CreateRemoteThread",
        source="imports",
        category="process_injection",
        weight=35,
        description="Import de CreateRemoteThread — injeção de código em processo remoto",
    ),
    HeuristicRule(
        id="INJ_WRITEPROCESSMEMORY",
        signal="WriteProcessMemory",
        source="imports",
        category="process_injection",
        weight=30,
        description="Import de WriteProcessMemory — escrita em memória de processo externo",
    ),
    HeuristicRule(
        id="INJ_VIRTUALALLOCEX",
        signal="VirtualAllocEx",
        source="imports",
        category="process_injection",
        weight=30,
        description="Import de VirtualAllocEx — alocação em processo remoto",
    ),

    # Download remoto
    HeuristicRule(
        id="DL_URLDOWNLOADTOFILE",
        signal="URLDownloadToFile",
        source="imports",
        category="remote_download",
        weight=25,
        description="Import de URLDownloadToFile — download remoto de arquivo",
    ),

    # PowerShell ofuscado
    HeuristicRule(
        id="PS_ENCODEDCOMMAND",
        signal="EncodedCommand",
        source="strings",
        category="obfuscation",
        weight=30,
        description="EncodedCommand — PowerShell com payload Base64",
    ),
    HeuristicRule(
        id="PS_EXECUTIONPOLICY_BYPASS",
        signal="ExecutionPolicy Bypass",
        source="strings",
        category="obfuscation",
        weight=25,
        description="ExecutionPolicy Bypass — evasão de política de execução",
    ),

    # -- SINAIS MEDIOS -------------------------------------------------------

    HeuristicRule(
        id="PERSIST_RUN",
        signal="CurrentVersion\\Run",
        source="strings",
        category="persistence",
        weight=20,
        description="Referência a chave Run no registro — possível persistência",
    ),
    HeuristicRule(
        id="PERSIST_RUNONCE",
        signal="CurrentVersion\\RunOnce",
        source="strings",
        category="persistence",
        weight=20,
        description="Referência a chave RunOnce no registro",
    ),
    HeuristicRule(
        id="AUTO_POWERSHELL",
        signal="powershell",
        source="strings",
        category="suspicious_automation",
        weight=15,
        description="Referência a powershell nas strings",
    ),
    HeuristicRule(
        id="AUTO_SCHTASKS",
        signal="schtasks",
        source="strings",
        category="suspicious_automation",
        weight=15,
        description="Referência a schtasks — agendamento de tarefas",
    ),
    HeuristicRule(
        id="CTX_CRACK",
        signal_regex=r"crack|keygen|serial\s+key|activat",
        source="strings",
        category="suspicious_context",
        weight=20,
        description="Palavras associadas a cracks/keygens/ativações ilegítimas",
    ),

    # -- SINAIS FRACOS / CONTEXTUAIS ----------------------------------------
    HeuristicRule(
        id="WEAK_UNSIGNED",
        signal="unsigned",
        source="signature",
        category="weak_context",
        weight=10,
        description="Executável sem assinatura digital",
    ),
    HeuristicRule(
        id="WEAK_APPDATA",
        signal="%AppData%",
        source="strings",
        category="weak_context",
        weight=5,
        description="Referência a %AppData%",
    ),
    HeuristicRule(
        id="WEAK_TEMP",
        signal="%Temp%",
        source="strings",
        category="weak_context",
        weight=5,
        description="Referência a %Temp%",
    ),
    HeuristicRule(
        id="WEAK_STARTUP",
        signal="%Startup%",
        source="strings",
        category="weak_context",
        weight=8,
        description="Referência a pasta Startup",
    ),
    HeuristicRule(
        id="WEAK_TASKKILL",
        signal="taskkill",
        source="strings",
        category="weak_context",
        weight=5,
        description="Referência a taskkill",
    ),
    HeuristicRule(
        id="WEAK_MULTIPLE_URLS",
        signal="url_count > 3",
        source="iocs",
        category="weak_context",
        weight=8,
        description="Múltiplas URLs detectadas",
    ),
]

WEAK_CONTEXT_CAP = 20

RECOMMENDATIONS_BY_CATEGORY = {
    "process_injection": "Detectados imports de injeção de processo. Risco elevado de código malicioso que injeta em outros processos.",
    "remote_download": "Detectado download remoto via URLDownloadToFile. O executável pode baixar payloads adicionais.",
    "obfuscation": "Detectados indicadores de ofuscação (PowerShell codificado/bypass). Análise em sandbox recomendada.",
    "persistence": "Detectadas referências a chaves de registro de persistência (Run/RunOnce). Possível mecanismo de persistência.",
    "suspicious_automation": "Detectadas referências a ferramentas de automação suspeitas (schtasks, taskkill, powershell).",
    "suspicious_context": "Detectadas strings associadas a software ilegítimo (crack, keygen, serial).",
    "weak_context": "Indicadores contextuais detectados. Podem ser legítimos dependendo do contexto de uso.",
}
