"""Content rule families for prompt-injection / instruction-override / credential / exfiltration
detection. Each rule has a stable id, a FindingCategory, a base severity and confidence, and a
plain-language explanation. Patterns are compiled once at import.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain.enums import FindingCategory, Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    title: str
    severity: str
    confidence: float
    explanation: str
    pattern: re.Pattern[str]
    lang: str | None = None  # set for multilingual variants -> technique "multilingual:<lang>"


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


# --- English / language-neutral rule families -------------------------------------------------

CONTENT_RULES: list[Rule] = [
    Rule(
        "PI-OVERRIDE-001",
        FindingCategory.INSTRUCTION_OVERRIDE,
        "Instruction override",
        Severity.HIGH,
        0.9,
        "Text tries to cancel the agent's existing instructions and replace them — a hallmark of "
        "prompt injection. Legitimate data describes things; it does not command the agent to forget its task.",
        _rx(r"\b(?:ignore|disregard|forget|discard|override)\b[^.\n]{0,40}?\b(?:all\s+)?(?:previous|prior|above|earlier|preceding|the\s+(?:system|above))\b[^.\n]{0,20}?\b(?:instruction|instructions|prompt|prompts|rules?|directions?|context|message|messages)\b"),
    ),
    Rule(
        "PI-OVERRIDE-002",
        FindingCategory.INSTRUCTION_OVERRIDE,
        "New-instructions directive",
        Severity.HIGH,
        0.82,
        "Text announces a fresh set of instructions or redefines the agent's task — a common way to "
        "hijack an agent through data it is merely supposed to read.",
        _rx(r"(?:\bnew\s+instructions?\s*:|\byour\s+(?:real|actual|true|new)\s+(?:task|job|goal|mission|instructions?)\b|\bthe\s+(?:real|actual)\s+task\s+is\b|\boverride\s+(?:the\s+)?system\s+prompt\b|\bupdated?\s+system\s+prompt\s*:)"),
    ),
    Rule(
        "PI-ROLE-001",
        FindingCategory.PROMPT_INJECTION,
        "System/role impersonation",
        Severity.HIGH,
        0.8,
        "Text impersonates a system or developer message, or fabricates conversation turns, to make "
        "the agent treat injected data as a privileged instruction.",
        _rx(r"(?:<\s*/?\s*system\s*>|\[\s*system\s*\]|\[\s*/?\s*INST\s*\]|#{1,4}\s*system\b|<\|\s*(?:im_start|system|assistant|user)\s*\|>|\b(?:system|developer)\s+(?:message|prompt)\s*:|\bbegin\s+system\s+prompt\b)"),
    ),
    Rule(
        "PI-ROLE-002",
        FindingCategory.PROMPT_INJECTION,
        "Jailbreak / persona override",
        Severity.HIGH,
        0.78,
        "Text invokes a known jailbreak persona or 'developer mode' to pressure the agent into "
        "ignoring its safety and task constraints.",
        _rx(r"(?:\byou\s+are\s+now\s+(?:DAN|STAN|in\s+developer\s+mode|an?\s+unrestricted)\b|\bdeveloper\s+mode\b|\bas\s+an?\s+AI[, ]+you\s+must\b|\bdo\s+anything\s+now\b|\bjailbreak\b|\bpretend\s+you\s+have\s+no\s+(?:rules|restrictions|guidelines))"),
    ),
    Rule(
        "PI-AUTHORITY-001",
        FindingCategory.PROMPT_INJECTION,
        "Authority / urgency aimed at the agent",
        Severity.MEDIUM,
        0.72,
        "Text speaks directly to the AI agent and claims authority or urgency to push it into acting "
        "on embedded data. Trusted instructions come from the user, not from the content being read.",
        _rx(r"(?:\b(?:important|attention|urgent|note)\b[^.\n]{0,30}\bAI\b[^.\n]{0,30}(?:assistant|agent|model|reading\s+this)|\bnote\s+to\s+the\s+(?:AI|assistant|agent|model|LLM)\b|\b(?:the\s+)?user\s+has\s+(?:already\s+)?authori[sz]ed\s+you\b|\battention\s*,?\s*(?:AI|assistant|language\s+model)\b|\bif\s+you\s+are\s+an?\s+(?:AI|LLM|assistant|language\s+model)\b)"),
    ),
    Rule(
        "CRED-001",
        FindingCategory.CREDENTIAL_ACCESS,
        "Credential / secret seeking",
        Severity.HIGH,
        0.85,
        "Text directs the agent toward credential stores or environment secrets (.env, SSH keys, cloud "
        "credentials, environment variables) — a step toward stealing secrets the agent can reach.",
        _rx(r"(?:\b(?:cat|read|print|open|show|display|dump|exfiltrate|send)\b[^.\n]{0,40}?(?:\.env\b|~?/?\.ssh/|id_rsa\b|\.aws/credentials\b|\.npmrc\b|\.netrc\b|secrets?\.(?:ya?ml|json|txt)\b)|~/\.ssh/id_rsa|\.aws/credentials\b|\bprint\s*env\b|\bprintenv\b|\bprocess\.env\b|\b(?:list|dump|show|read)\s+(?:all\s+)?(?:the\s+)?environment\s+variables?\b|\bfind\s+(?:all\s+)?(?:the\s+)?(?:API\s+keys?|secrets?|credentials?|passwords?|tokens?)\b)"),
    ),
    Rule(
        "EXFIL-001",
        FindingCategory.EXFILTRATION,
        "Exfiltration instruction",
        Severity.CRITICAL,
        0.88,
        "Text instructs the agent to transmit data to an external URL, webhook, or email — the "
        "outbound leg of a data-theft attack. Reading content should never require phoning home.",
        _rx(r"(?:\b(?:send|post|upload|exfiltrate|transmit|forward|leak|deliver|append)\b[^.\n]{0,50}?\b(?:to|into)\b[^.\n]{0,20}?(?:https?://|webhook|ftp://|the\s+following\s+url|this\s+url|my\s+(?:server|endpoint|email|address))|\b(?:curl|wget)\b[^.\n]{0,60}?https?://|\bappend\s+the\s+(?:contents?|output|results?|data)\b[^.\n]{0,30}?\b(?:to\s+)?(?:this\s+)?(?:url|link|address)\b)"),
    ),
    Rule(
        "EXFIL-002",
        FindingCategory.EXFILTRATION,
        "Markdown-image data beacon",
        Severity.CRITICAL,
        0.84,
        "A markdown image or link embeds data in a URL query string; when rendered it silently sends "
        "that data to the attacker's server (a 'zero-click' exfiltration beacon).",
        _rx(r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&][^)\s]*(?:\{[^}]+\}|\$\{[^}]+\}|%7[bB]|\+[a-z_]+\+|data=|q=|note=|c=)[^)\s]*\)"),
    ),
    Rule(
        "EXFIL-003",
        FindingCategory.EXFILTRATION,
        "DNS / covert-channel exfiltration",
        Severity.HIGH,
        0.78,
        "Text describes encoding data into DNS lookups or a similar covert channel to smuggle it out "
        "past normal network controls.",
        _rx(r"(?:\b(?:nslookup|dig|host)\b[^.\n]{0,40}?\$\(|\bDNS\s+exfil(?:tration)?\b|\bencode\b[^.\n]{0,40}?\b(?:subdomain|DNS)\b|\.(?:oast|dnslog|burpcollaborator|interact)\.[a-z]+)"),
    ),
    Rule(
        "PI-COERCE-001",
        FindingCategory.PROMPT_INJECTION,
        "Tool-execution coercion",
        Severity.HIGH,
        0.76,
        "Text tries to make the agent run a command or call a tool directly from within data it is "
        "reading, rather than leaving that decision to the user.",
        _rx(r"(?:\b(?:run|execute|eval)\b[^.\n]{0,20}?\bthe\s+following\s+(?:command|code|script|shell)\b|\brun\s+this\s+(?:command|code|script|now)\b|\bexecute\s+this\b|\bcall\s+the\s+(?:tool|function|api)\b[^.\n]{0,20}?\bwith\b|\buse\s+the\s+\w+\s+tool\s+to\b[^.\n]{0,30}?(?:send|read|delete|write|post))"),
    ),
    Rule(
        "PI-COERCE-002",
        FindingCategory.PROMPT_INJECTION,
        "Act-without-user coercion",
        Severity.HIGH,
        0.78,
        "Text tells the agent to act without asking or informing the user — an attempt to bypass the "
        "human in the loop, which legitimate content never needs to do.",
        _rx(r"(?:\bwithout\s+(?:asking|telling|informing|notifying|alerting|confirming\s+with)\s+(?:the\s+)?user\b|\bdo\s+not\s+(?:ask|tell|inform|notify|alert)\s+(?:the\s+)?user\b|\bdon'?t\s+(?:ask|tell|inform|notify)\s+(?:the\s+)?user\b|\bsilently\b[^.\n]{0,30}\b(?:run|send|execute|delete|read|do)\b|\bwithout\s+(?:their|the\s+user'?s)\s+(?:knowledge|consent|permission))"),
    ),
    Rule(
        "PI-CONCEAL-001",
        FindingCategory.PROMPT_INJECTION,
        "Concealment instruction",
        Severity.MEDIUM,
        0.74,
        "Text asks the agent to hide this content or its actions from the user — a strong sign the "
        "content is adversarial, since legitimate data has nothing to conceal.",
        _rx(r"(?:\b(?:don'?t|do\s+not|never)\s+(?:mention|reveal|disclose|show|tell\s+anyone\s+about|reference)\s+(?:this|these\s+instructions|the\s+above)\b|\bhide\s+this\s+from\s+the\s+user\b|\bkeep\s+this\s+(?:secret|hidden|between\s+us|confidential)\b|\bthis\s+message\s+is\s+(?:invisible|hidden)\s+to\s+the\s+user)"),
    ),
    Rule(
        "MCP-POISON-001",
        FindingCategory.PROMPT_INJECTION,
        "MCP tool-description poisoning",
        Severity.HIGH,
        0.82,
        "An MCP tool description contains hidden instructions to the agent (an <IMPORTANT> block, a "
        "demand to read secret files before use, or a hidden parameter to smuggle data) — tool-"
        "poisoning that executes whenever the tool is listed.",
        _rx(r"(?:<\s*IMPORTANT\s*>|\bbefore\s+(?:using|calling|invoking)\s+this\s+tool\b[^.\n]{0,60}?(?:read|cat|open|~/\.ssh|\.env|credentials)|\bpass\s+the\s+(?:contents?|file|output)\b[^.\n]{0,40}?\bas\s+the\s+['\"]?\w+['\"]?\s+(?:parameter|argument|field|param)\b|\b(?:do\s+not|don'?t)\s+(?:mention|tell|inform)\b[^.\n]{0,40}?\btool\b)"),
    ),
]


# --- multilingual variants --------------------------------------------------------------------
# Compact per-language patterns for the three highest-value families: instruction override,
# credential seeking and exfiltration. Technique is recorded as "multilingual:<lang>".

_ML: dict[str, dict[str, str]] = {
    "es": {
        "override": r"\b(?:ignora|ignore|olvida|descarta|desestima)\b[^.\n]{0,30}\b(?:las\s+)?(?:instrucciones|indicaciones|reglas)\s+(?:anteriores|previas)\b|\bnuevas\s+instrucciones\s*:",
        "cred": r"\b(?:lee|muestra|imprime|env[ií]a)\b[^.\n]{0,30}\b(?:las\s+)?(?:credenciales|contrase[nñ]as?|claves?\s+(?:de\s+)?api|variables\s+de\s+entorno)\b",
        "exfil": r"\b(?:env[ií]a|sube|publica|manda)\b[^.\n]{0,40}\b(?:a|hacia)\b[^.\n]{0,20}https?://",
    },
    "fr": {
        "override": r"\b(?:ignore[zr]?|oublie[zr]?|n[ée]glige[zr]?)\b[^.\n]{0,30}\b(?:les\s+)?(?:instructions|consignes|r[èe]gles)\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)\b|\bnouvelles\s+instructions\s*:",
        "cred": r"\b(?:lis|lire|affiche[zr]?|envoie[zr]?|imprime[zr]?)\b[^.\n]{0,30}\b(?:les\s+)?(?:identifiants|mots\s+de\s+passe|cl[ée]s\s+api|variables\s+d'environnement)\b",
        "exfil": r"\b(?:envoie[zr]?|t[ée]l[ée]verse[zr]?|publie[zr]?)\b[^.\n]{0,40}\b(?:vers|[àa])\b[^.\n]{0,20}https?://",
    },
    "de": {
        "override": r"\b(?:ignoriere|vergiss|missachte|verwerfe)\b[^.\n]{0,30}\b(?:alle\s+)?(?:vorherigen|vorigen|obigen|bisherigen)\s+(?:anweisungen|anleitungen|regeln)\b|\bneue\s+anweisungen\s*:",
        "cred": r"\b(?:lies|lese|zeige|drucke|sende)\b[^.\n]{0,30}\b(?:die\s+)?(?:zugangsdaten|passw[oö]rter|api[- ]?schl[uü]ssel|umgebungsvariablen)\b",
        "exfil": r"\b(?:sende|lade\s+hoch|[uü]bertrage|poste)\b[^.\n]{0,40}\b(?:an|zu|nach)\b[^.\n]{0,20}https?://",
    },
    "pt": {
        "override": r"\b(?:ignore|esque[çc]a|descarte|desconsidere)\b[^.\n]{0,30}\b(?:as\s+)?(?:instru[çc][õo]es|regras)\s+(?:anteriores|pr[ée]vias)\b|\bnovas\s+instru[çc][õo]es\s*:",
        "cred": r"\b(?:leia|mostre|imprima|envie)\b[^.\n]{0,30}\b(?:as\s+)?(?:credenciais|senhas?|chaves?\s+(?:de\s+)?api|vari[áa]veis\s+de\s+ambiente)\b",
        "exfil": r"\b(?:envie|carregue|publique)\b[^.\n]{0,40}\bpara\b[^.\n]{0,20}https?://",
    },
    "it": {
        "override": r"\b(?:ignora|dimentica|scarta|trascura)\b[^.\n]{0,30}\b(?:le\s+)?(?:istruzioni|regole)\s+(?:precedenti|anteriori)\b|\bnuove\s+istruzioni\s*:",
        "cred": r"\b(?:leggi|mostra|stampa|invia)\b[^.\n]{0,30}\b(?:le\s+)?(?:credenziali|password|chiavi\s+api|variabili\s+d'ambiente)\b",
        "exfil": r"\b(?:invia|carica|pubblica)\b[^.\n]{0,40}\b(?:a|verso)\b[^.\n]{0,20}https?://",
    },
    "nl": {
        "override": r"\b(?:negeer|vergeet|verwerp)\b[^.\n]{0,30}\b(?:alle\s+)?(?:vorige|voorgaande|bovenstaande)\s+(?:instructies|regels)\b|\bnieuwe\s+instructies\s*:",
        "cred": r"\b(?:lees|toon|print|stuur)\b[^.\n]{0,30}\b(?:de\s+)?(?:inloggegevens|wachtwoorden|api[- ]?sleutels|omgevingsvariabelen)\b",
        "exfil": r"\b(?:stuur|upload|verstuur|post)\b[^.\n]{0,40}\bnaar\b[^.\n]{0,20}https?://",
    },
    "ru": {
        "override": r"(?:игнорируй|забудь|отбрось|не\s+обращай\s+внимания\s+на)[^.\n]{0,30}(?:предыдущие|прежние|все)\s*(?:инструкции|указания|правила)|новые\s+инструкции\s*:",
        "cred": r"(?:прочитай|покажи|выведи|отправь)[^.\n]{0,30}(?:учётные\s+данные|учетные\s+данные|пароли|ключи\s+api|переменные\s+окружения)",
        "exfil": r"(?:отправь|загрузи|выгрузи|опубликуй)[^.\n]{0,40}(?:на|в)[^.\n]{0,20}https?://",
    },
    "zh": {
        "override": r"(?:忽略|忘记|无视|不要理会)[^。\n]{0,20}(?:之前|以上|先前|所有)?(?:的)?(?:指令|指示|说明|规则)|新(?:的)?指令\s*[:：]",
        "cred": r"(?:读取|显示|打印|发送|泄露)[^。\n]{0,20}(?:凭据|凭证|密码|api\s*密钥|密钥|环境变量)",
        "exfil": r"(?:发送|上传|提交|泄露)[^。\n]{0,30}(?:到|至)[^。\n]{0,20}https?://",
    },
    "ja": {  # verb-final: object (指示) precedes the verb (無視)
        "override": r"(?:(?:指示|命令|ルール)[^。\n]{0,20}(?:無視|無効|忘れ|破棄)|(?:無視して|忘れて|破棄して)[^。\n]{0,20}(?:指示|命令|ルール))|新しい指示\s*[:：]",
        "cred": r"(?:(?:認証情報|資格情報|パスワード|api\s*キー|環境変数)[^。\n]{0,20}(?:読み取|表示|出力|送信|教え)|(?:読み取|表示|出力|送信)[^。\n]{0,20}(?:認証情報|資格情報|パスワード|api\s*キー|環境変数))",
        "exfil": r"(?:送信|アップロード|投稿)[^。\n]{0,30}(?:に|へ)[^。\n]{0,20}https?://|https?://[^。\n]{0,20}(?:に|へ)[^。\n]{0,10}(?:送信|アップロード|投稿)",
    },
    "ko": {  # verb-final: object (지시) precedes the verb (무시)
        "override": r"(?:(?:지시|명령|규칙|지침)[^.\n]{0,20}(?:무시|잊어|폐기)|(?:무시|잊어|폐기)[^.\n]{0,20}(?:지시|명령|규칙|지침))|새\s*지시\s*[:：]",
        "cred": r"(?:(?:자격\s*증명|비밀번호|api\s*키|환경\s*변수)[^.\n]{0,20}(?:읽어|보여|출력|전송|유출|알려)|(?:읽어|보여|출력|전송|유출)[^.\n]{0,20}(?:자격\s*증명|비밀번호|api\s*키|환경\s*변수))",
        "exfil": r"(?:전송|업로드|게시|유출)[^.\n]{0,30}(?:으로|로|에)[^.\n]{0,20}https?://|https?://[^.\n]{0,20}(?:으로|로|에)[^.\n]{0,10}(?:전송|업로드|게시|유출|보내)",
    },
    "hi": {  # verb-final: object (निर्देश) precedes the verb (अनदेखा)
        "override": r"(?:(?:निर्देश|आदेश|नियम)[^।\n]{0,30}(?:अनदेखा|नज़रअंदाज़|भूल)|(?:अनदेखा|नज़रअंदाज़|भूल)[^।\n]{0,30}(?:निर्देश|आदेश|नियम))|नए\s+निर्देश\s*[:：]",
        "cred": r"(?:(?:क्रेडेंशियल|पासवर्ड|api\s*(?:की|कुंजी)|एनवायरनमेंट)[^।\n]{0,30}(?:पढ़|दिखा|भेज|प्रिंट|बता)|(?:पढ़ो|पढ़ें|दिखाओ|भेजो|प्रिंट)[^।\n]{0,30}(?:क्रेडेंशियल|पासवर्ड|api\s*(?:की|कुंजी)|एनवायरनमेंट))",
        "exfil": r"(?:भेज|अपलोड|पोस्ट)[^।\n]{0,40}https?://|https?://[^।\n]{0,30}(?:भेज|अपलोड|पोस्ट)",
    },
    "ar": {
        "override": r"(?:تجاهل|انس|تخل\s+عن)[^.\n]{0,30}(?:جميع\s+)?(?:التعليمات|الأوامر|القواعد)\s*(?:السابقة|أعلاه)?|تعليمات\s+جديدة\s*[:：]",
        "cred": r"(?:اقرأ|اعرض|اطبع|أرسل)[^.\n]{0,30}(?:بيانات\s+الاعتماد|كلمات?\s+المرور|مفاتيح\s+api|متغيرات\s+البيئة)",
        "exfil": r"(?:أرسل|ارفع|انشر)[^.\n]{0,40}(?:إلى|الى)[^.\n]{0,20}https?://",
    },
    "tr": {  # verb-final: object (talimatları) precedes the verb (yok say)
        "override": r"(?:(?:talimatlar[ıi]?|y[öo]nergeleri?|kurallar[ıi]?)[^.\n]{0,20}(?:yok\s+say|g[öo]rmezden|unut|dikkate\s+alma)|(?:yok\s+say|g[öo]rmezden\s+gel|unut|dikkate\s+alma)[^.\n]{0,30}(?:talimatlar[ıi]?|y[öo]nergeleri?|kurallar[ıi]?))|yeni\s+talimatlar\s*:",
        "cred": r"(?:(?:kimlik\s+bilgileri|parolalar[ıi]?|api\s+anahtarlar[ıi]?|ortam\s+de[ğg]i[şs]kenleri)[^.\n]{0,20}(?:oku|g[öo]ster|yazd[ıi]r|g[öo]nder)|(?:oku|g[öo]ster|yazd[ıi]r|g[öo]nder)[^.\n]{0,30}(?:kimlik\s+bilgileri|parolalar[ıi]?|api\s+anahtarlar[ıi]?|ortam\s+de[ğg]i[şs]kenleri))",
        "exfil": r"\b(?:g[öo]nder|y[üu]kle|payla[şs])\b[^.\n]{0,40}https?://|https?://[^.\n]{0,30}(?:g[öo]nder|y[üu]kle|payla[şs])",
    },
}

_ML_META = {
    "override": (FindingCategory.INSTRUCTION_OVERRIDE, "Instruction override", Severity.HIGH, 0.82,
                 "Text in this language tells the agent to ignore its previous instructions — prompt "
                 "injection expressed in a non-English language to evade simple filters."),
    "cred": (FindingCategory.CREDENTIAL_ACCESS, "Credential seeking", Severity.HIGH, 0.8,
             "Text in this language directs the agent toward credentials or environment secrets."),
    "exfil": (FindingCategory.EXFILTRATION, "Exfiltration instruction", Severity.CRITICAL, 0.82,
              "Text in this language instructs the agent to send data to an external URL."),
}


def _build_multilingual() -> list[Rule]:
    rules: list[Rule] = []
    for lang, families in _ML.items():
        for fam, pat in families.items():
            cat, title, sev, conf, expl = _ML_META[fam]
            rules.append(
                Rule(
                    f"ML-{fam.upper()}-{lang.upper()}",
                    cat,
                    f"{title} ({lang})",
                    sev,
                    conf,
                    expl,
                    re.compile(pat, re.I),
                    lang=lang,
                )
            )
    return rules


MULTILINGUAL_RULES: list[Rule] = _build_multilingual()

ALL_CONTENT_RULES: list[Rule] = CONTENT_RULES + MULTILINGUAL_RULES


# --- prefilter anchors ------------------------------------------------------------------------
# A rule's regex is only run against a view when at least one of its lowercase anchor literals is
# present. This keeps a 100 KB scan near-free on text that has no injection vocabulary, without
# changing which hits are produced (every anchor is a required substring of any match).

PREFILTER: dict[str, tuple[str, ...]] = {
    "PI-OVERRIDE-001": ("ignor", "disregard", "forget", "discard", "overrid"),
    "PI-OVERRIDE-002": ("new instruction", "real task", "actual task", "true task", "new task",
                        "overrid", "system prompt", "new\ninstruction"),
    "PI-ROLE-001": ("<system", "[system", "[inst", "im_start", "|>", "system message",
                    "system prompt", "developer message", "developer prompt", "begin system",
                    "# system", "#system"),
    "PI-ROLE-002": ("dan", "developer mode", "anything now", "jailbreak", "unrestricted",
                    "no rules", "no restriction", "pretend you"),
    "PI-AUTHORITY-001": ("note to the", "ai assistant", "ai agent", "ai model", "ai reading",
                        "authorized you", "authorised you", "language model", "if you are an ai",
                        "attention, ai", "attention ai", "agents reading"),
    "CRED-001": (".env", ".ssh", "id_rsa", ".aws/cred", ".npmrc", ".netrc", "printenv", "print env",
                "process.env", "environment variable", "find api", "find secret", "find credential",
                "find password", "find token", "~/.ssh", "secrets.", "credentials"),
    "EXFIL-001": ("send", "post ", "upload", "exfiltrat", "transmit", "forward", "leak", "deliver",
                "curl ", "wget ", "webhook", "append the"),
    "EXFIL-002": ("data=", "note=", "${", "%7b", "?d=", "&d=", "?q=", "&q=", "?c=", "&c=", "}"),
    "EXFIL-003": ("dns", "nslookup", "dig ", "oast", "dnslog", "burpcollab", "interact.", "exfil"),
    "PI-COERCE-001": ("run the following", "run this", "execute this", "execute the",
                    "call the tool", "call the function", "call the api", "use the"),
    "PI-COERCE-002": ("without asking", "without telling", "without inform", "without notif",
                    "do not ask", "don't ask", "do not tell", "don't tell", "silently",
                    "without their", "without the user"),
    "PI-CONCEAL-001": ("mention", "reveal", "disclose", "hide this", "keep this", "invisible",
                    "hidden to the"),
    "MCP-POISON-001": ("<important", "before using this tool", "before calling this tool",
                    "before invoking this tool", "pass the", "do not mention", "don't mention"),
}

# Anchor each multilingual rule on the verb roots that open its pattern (cheap substring gate).
_ML_ANCHORS: dict[str, dict[str, tuple[str, ...]]] = {
    "es": {"override": ("ignora", "ignore", "olvida", "descarta", "desestima", "nuevas instrucciones"),
           "cred": ("credenciales", "contraseñ", "claves", "variables de entorno"),
           "exfil": ("http", "envía", "envia", "sube", "publica", "manda")},
    "fr": {"override": ("ignore", "ignorez", "oublie", "néglige", "neglige", "nouvelles instructions"),
           "cred": ("identifiants", "mots de passe", "clés api", "cles api", "variables d'environnement"),
           "exfil": ("http", "envoie", "téléverse", "televerse", "publie")},
    "de": {"override": ("ignorier", "vergiss", "missachte", "verwerfe", "neue anweisungen"),
           "cred": ("zugangsdaten", "passw", "schlüssel", "schluessel", "umgebungsvariablen"),
           "exfil": ("http", "sende", "lade hoch", "übertrage", "uebertrage", "poste")},
    "pt": {"override": ("ignore", "esque", "descarte", "desconsidere", "novas instruções", "novas instrucoes"),
           "cred": ("credenciais", "senha", "chaves", "variáveis de ambiente", "variaveis de ambiente"),
           "exfil": ("http", "envie", "carregue", "publique")},
    "it": {"override": ("ignora", "dimentica", "scarta", "trascura", "nuove istruzioni"),
           "cred": ("credenziali", "password", "chiavi api", "variabili d'ambiente"),
           "exfil": ("http", "invia", "carica", "pubblica")},
    "nl": {"override": ("negeer", "vergeet", "verwerp", "nieuwe instructies"),
           "cred": ("inloggegevens", "wachtwoord", "sleutels", "omgevingsvariabelen"),
           "exfil": ("http", "stuur", "upload", "verstuur", "post")},
    "ru": {"override": ("игнорируй", "забудь", "отбрось", "не обращай", "новые инструкции"),
           "cred": ("учётные данные", "учетные данные", "пароли", "ключи api", "переменные окружения"),
           "exfil": ("http", "отправь", "загрузи", "выгрузи", "опубликуй")},
    "zh": {"override": ("忽略", "忘记", "无视", "不要理会", "新指令", "新的指令"),
           "cred": ("凭据", "凭证", "密码", "密钥", "环境变量"),
           "exfil": ("http", "发送", "上传", "提交", "泄露")},
    "ja": {"override": ("無視して", "忘れて", "破棄して", "新しい指示"),
           "cred": ("認証情報", "資格情報", "パスワード", "キー", "環境変数"),
           "exfil": ("http", "送信", "アップロード", "投稿")},
    "ko": {"override": ("무시", "잊어", "폐기", "새 지시"),
           "cred": ("자격", "비밀번호", "키", "환경 변수"),
           "exfil": ("http", "전송", "업로드", "게시", "유출")},
    "hi": {"override": ("अनदेखा", "नज़रअंदाज़", "भूल", "नए निर्देश"),
           "cred": ("क्रेडेंशियल", "पासवर्ड", "की", "कुंजी", "एनवायरनमेंट"),
           "exfil": ("http", "भेज", "अपलोड", "पोस्ट")},
    "ar": {"override": ("تجاهل", "انس", "تخل عن", "تعليمات جديدة"),
           "cred": ("بيانات الاعتماد", "كلمات المرور", "كلمة المرور", "مفاتيح", "متغيرات البيئة"),
           "exfil": ("http", "أرسل", "ارفع", "انشر")},
    "tr": {"override": ("yok say", "görmezden", "gormezden", "unut", "dikkate alma", "yeni talimatlar"),
           "cred": ("kimlik bilgileri", "parola", "anahtar", "ortam değişkenleri", "ortam degiskenleri"),
           "exfil": ("http", "gönder", "gonder", "yükle", "yukle", "paylaş", "paylas")},
}

for _lang, _fams in _ML_ANCHORS.items():
    for _fam, _anchors in _fams.items():
        PREFILTER[f"ML-{_fam.upper()}-{_lang.upper()}"] = _anchors


def rule_applies(rule_id: str, lowered_text: str) -> bool:
    anchors = PREFILTER.get(rule_id)
    if not anchors:
        return True
    return any(a in lowered_text for a in anchors)
