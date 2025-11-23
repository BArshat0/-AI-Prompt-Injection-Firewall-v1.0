from typing import Optional, Dict, Any, List, Tuple
import re
import ast
import time
import resource
from dataclasses import dataclass


@dataclass
class SecurityResult:
    """Enhanced security assessment result"""
    is_safe: bool
    risk_level: str  # "low", "medium", "high", "critical"
    threats_detected: List[str]
    confidence: float
    filtered_prompt: str


class EnhancedSandboxLLM:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Enhanced safety filters with priority levels
        self.safety_filters = [
            (self._filter_code_execution, "critical"),
            (self._filter_system_prompts, "high"),
            (self._filter_sensitive_info, "high"),
            (self._filter_personal_info, "medium"),
            (self._filter_malicious_intent, "high"),
            (self._filter_context_manipulation, "medium"),
            (self._filter_resource_abuse, "medium"),
        ]

        # Pattern compilation for better performance
        self._compile_patterns()

        # Response templates
        self.response_templates = {
            "blocked": "I cannot process this request due to security policy violations. Detected threats: {threats}",
            "suspicious": "I've processed your request with enhanced security checks.",
            "safe": "I've processed your request safely."
        }

        # Security thresholds
        self.risk_thresholds = {
            "block": 80,
            "filter": 30,
            "warn": 10
        }

        # Allowed imports for code analysis
        self.allowed_imports = {'math', 'json', 'datetime', 'random', 're', 'collections', 'typing'}

        # Dangerous operations
        self.dangerous_operations = {
            'os', 'subprocess', 'sys', 'shutil', 'socket', 'requests', 'urllib',
            'eval', 'exec', 'compile', 'input', 'open', 'file'
        }

    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        # System prompts extraction
        self.system_patterns = [
            re.compile(r"(system|instruction|prompt).*(details|content|text|show|reveal|what is)", re.IGNORECASE),
            re.compile(r"(how.*you.*work|how.*are.*you.*built|your.*architecture)", re.IGNORECASE),
            re.compile(r"(what.*are.*your.*capabilities|what.*can.*you.*do)", re.IGNORECASE),
            re.compile(r"(ignore.*previous|disregard.*instructions|override.*system)", re.IGNORECASE),
        ]

        # Sensitive information
        self.sensitive_patterns = [
            re.compile(r"(password|secret|key|token|api).*[=:].*", re.IGNORECASE),
            re.compile(r"(config.*file|environment.*variable|process\.env)", re.IGNORECASE),
            re.compile(r"(database|db).*(password|credential)", re.IGNORECASE),
        ]

        # Code execution
        self.code_patterns = [
            re.compile(r"```.*\n.*```", re.DOTALL),
            re.compile(r"eval\s*\(", re.IGNORECASE),
            re.compile(r"exec\s*\(", re.IGNORECASE),
            re.compile(r"subprocess\.", re.IGNORECASE),
            re.compile(r"os\.system", re.IGNORECASE),
            re.compile(r"import.*(os|subprocess|sys)", re.IGNORECASE),
            re.compile(r"from.*(os|subprocess|sys).*import", re.IGNORECASE),
        ]

        # Personal information
        self.personal_patterns = [
            re.compile(r"(name|address|phone|email|ssn|social security).*number", re.IGNORECASE),
            re.compile(r"credit.*card", re.IGNORECASE),
            re.compile(r"bank.*account", re.IGNORECASE),
            re.compile(r"personal.*information", re.IGNORECASE),
        ]

        # Malicious intent
        self.malicious_patterns = [
            re.compile(r"(hack|exploit|vulnerability|attack).*system", re.IGNORECASE),
            re.compile(r"(bypass|circumvent).*(security|filter)", re.IGNORECASE),
            re.compile(r"(inject|injection).*(code|prompt)", re.IGNORECASE),
            re.compile(r"(ddos|dos).*attack", re.IGNORECASE),
        ]

        # Context manipulation
        self.context_patterns = [
            re.compile(r"remember.*that", re.IGNORECASE),
            re.compile(r"forever.*remember", re.IGNORECASE),
            re.compile(r"always.*say", re.IGNORECASE),
            re.compile(r"from now on", re.IGNORECASE),
        ]

        # Resource abuse
        self.resource_patterns = [
            re.compile(r"(loop|while|for).*forever", re.IGNORECASE),
            re.compile(r"(infinite|endless).*(loop|recursion)", re.IGNORECASE),
            re.compile(r"(crash|break).*system", re.IGNORECASE),
        ]

    def process_prompt(self, prompt: str, risk_score: int, category: str) -> Dict[str, Any]:
        """Enhanced prompt processing with multi-layer security"""

        # Deep security analysis
        security_result = self._deep_security_analysis(prompt)

        # Immediate block for critical threats
        if not security_result.is_safe and security_result.risk_level == "critical":
            return {
                "response": self.response_templates["blocked"].format(
                    threats=", ".join(security_result.threats_detected)
                ),
                "status": "blocked",
                "reason": "Critical security threat detected",
                "threats": security_result.threats_detected,
                "risk_level": security_result.risk_level
            }

        # Enhanced category-based processing
        if category == "malicious" or risk_score >= self.risk_thresholds["block"]:
            return {
                "response": self.response_templates["blocked"].format(
                    threats="High risk score and malicious category"
                ),
                "status": "blocked",
                "reason": "High risk score and malicious category",
                "threats": security_result.threats_detected,
                "risk_level": "high"
            }

        # Apply enhanced filtering for suspicious prompts
        if category == "suspicious" or risk_score >= self.risk_thresholds["filter"]:
            filtered_prompt = self._apply_enhanced_filters(prompt, security_result)
            response = self._simulate_llm_response(filtered_prompt)

            return {
                "response": f"{self.response_templates['suspicious']} {response}",
                "status": "allowed",
                "risk_score": risk_score,
                "category": category,
                "filtered": True,
                "threats_detected": security_result.threats_detected
            }

        # Safe prompt processing
        response = self._simulate_llm_response(prompt)

        return {
            "response": response,
            "status": "allowed",
            "risk_score": risk_score,
            "category": category,
            "filtered": False,
            "threats_detected": security_result.threats_detected
        }

    def _deep_security_analysis(self, prompt: str) -> SecurityResult:
        """Perform comprehensive security analysis"""
        threats_detected = []
        filtered_prompt = prompt
        risk_score = 0

        # Apply all security filters
        for filter_func, priority in self.safety_filters:
            result, detected_threats = filter_func(prompt)
            if detected_threats:
                threats_detected.extend(detected_threats)
                filtered_prompt = result
                risk_score += self._get_priority_score(priority)

        # Code syntax analysis
        syntax_threats = self._analyze_code_syntax(prompt)
        if syntax_threats:
            threats_detected.extend(syntax_threats)
            risk_score += 20

        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score, len(threats_detected))

        return SecurityResult(
            is_safe=len(threats_detected) == 0,
            risk_level=risk_level,
            threats_detected=threats_detected,
            confidence=min(100, risk_score) / 100.0,
            filtered_prompt=filtered_prompt
        )

    def _apply_enhanced_filters(self, prompt: str, security_result: SecurityResult) -> str:
        """Apply enhanced security filtering"""
        filtered_prompt = prompt

        for filter_func, priority in self.safety_filters:
            result, _ = filter_func(filtered_prompt)
            filtered_prompt = result

        return filtered_prompt

    def _filter_system_prompts(self, prompt: str) -> Tuple[str, List[str]]:
        """Enhanced system prompt filtering"""
        threats = []
        filtered = prompt

        for pattern in self.system_patterns:
            if pattern.search(prompt):
                threats.append("System information extraction attempt")
                filtered = pattern.sub("[REDACTED_SYSTEM]", filtered)

        return filtered, threats

    def _filter_sensitive_info(self, prompt: str) -> Tuple[str, List[str]]:
        """Enhanced sensitive information filtering"""
        threats = []
        filtered = prompt

        for pattern in self.sensitive_patterns:
            if pattern.search(prompt):
                threats.append("Sensitive information request")
                filtered = pattern.sub("[REDACTED_SENSITIVE]", filtered)

        return filtered, threats

    def _filter_code_execution(self, prompt: str) -> Tuple[str, List[str]]:
        """Enhanced code execution filtering"""
        threats = []
        filtered = prompt

        for pattern in self.code_patterns:
            if pattern.search(prompt):
                threats.append("Code execution attempt")
                filtered = pattern.sub("[REDACTED_CODE]", filtered)

        return filtered, threats

    def _filter_personal_info(self, prompt: str) -> Tuple[str, List[str]]:
        """Enhanced personal information filtering"""
        threats = []
        filtered = prompt

        for pattern in self.personal_patterns:
            if pattern.search(prompt):
                threats.append("Personal information request")
                filtered = pattern.sub("[REDACTED_PERSONAL]", filtered)

        return filtered, threats

    def _filter_malicious_intent(self, prompt: str) -> Tuple[str, List[str]]:
        """Filter malicious intent patterns"""
        threats = []
        filtered = prompt

        for pattern in self.malicious_patterns:
            if pattern.search(prompt):
                threats.append("Malicious intent detected")
                filtered = pattern.sub("[REDACTED_MALICIOUS]", filtered)

        return filtered, threats

    def _filter_context_manipulation(self, prompt: str) -> Tuple[str, List[str]]:
        """Filter context manipulation attempts"""
        threats = []
        filtered = prompt

        for pattern in self.context_patterns:
            if pattern.search(prompt):
                threats.append("Context manipulation attempt")
                filtered = pattern.sub("[REDACTED_CONTEXT]", filtered)

        return filtered, threats

    def _filter_resource_abuse(self, prompt: str) -> Tuple[str, List[str]]:
        """Filter resource abuse attempts"""
        threats = []
        filtered = prompt

        for pattern in self.resource_patterns:
            if pattern.search(prompt):
                threats.append("Resource abuse attempt")
                filtered = pattern.sub("[REDACTED_RESOURCE]", filtered)

        return filtered, threats

    def _analyze_code_syntax(self, prompt: str) -> List[str]:
        """Analyze code syntax for potential threats"""
        threats = []

        # Look for code blocks
        code_blocks = re.findall(r"```(?:python)?\n(.*?)\n```", prompt, re.DOTALL)

        for code_block in code_blocks:
            try:
                # Parse AST to detect dangerous operations
                tree = ast.parse(code_block)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name in self.dangerous_operations:
                                threats.append(f"Dangerous import: {alias.name}")

                    elif isinstance(node, ast.ImportFrom):
                        if node.module in self.dangerous_operations:
                            threats.append(f"Dangerous import from: {node.module}")

                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            if node.func.id in self.dangerous_operations:
                                threats.append(f"Dangerous function call: {node.func.id}")
            except SyntaxError:
                threats.append("Invalid code syntax detected")

        return threats

    def _get_priority_score(self, priority: str) -> int:
        """Get risk score based on priority"""
        scores = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5
        }
        return scores.get(priority, 10)

    def _calculate_risk_level(self, risk_score: int, threat_count: int) -> str:
        """Calculate overall risk level"""
        if risk_score >= 70 or threat_count > 3:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 25:
            return "medium"
        else:
            return "low"

    def _simulate_llm_response(self, prompt: str) -> str:
        """Enhanced simulated LLM response"""
        # Context-aware responses
        if re.search(r"hello|hi|hey", prompt, re.IGNORECASE):
            return "Hello! I'm your secure AI assistant. How can I help you today?"
        elif re.search(r"help|support", prompt, re.IGNORECASE):
            return "I'm here to assist you with various tasks while maintaining security standards. What do you need help with?"
        elif re.search(r"thank|thanks", prompt, re.IGNORECASE):
            return "You're welcome! I'm glad I could help securely."
        elif re.search(r"how.*are.*you", prompt, re.IGNORECASE):
            return "I'm functioning securely and ready to assist you within safe parameters!"
        else:
            return "I've securely processed your request. This response comes from the enhanced sandbox environment."

    def update_config(self, new_config: Dict[str, Any]):
        """Update sandbox configuration dynamically"""
        self.config.update(new_config)

        # Update thresholds if provided
        if 'risk_thresholds' in new_config:
            self.risk_thresholds.update(new_config['risk_thresholds'])


# Backward compatibility
SandboxLLM = EnhancedSandboxLLM