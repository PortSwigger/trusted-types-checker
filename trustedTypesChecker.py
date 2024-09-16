from burp import IBurpExtender, IScannerCheck, IScanIssue, IExtensionStateListener
from java.net import URL
import re

class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Trusted Types Checker")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        response_body = baseRequestResponse.getResponse()[response_info.getBodyOffset():].tostring()
        headers = response_info.getHeaders()
        status_code = response_info.getStatusCode()
        content_type = None
        for header in headers:
            if header.lower().startswith("content-type"):
                content_type = header.split(":")[1].strip().lower()

        if status_code == 200:
            if content_type and ("text/html" in content_type or "text/javascript" in content_type or "application/javascript" in content_type or "application/xhtml+xml" in content_type):
                match = re.search(r'trustedTypes\.createPolicy\s*\(\s*[\'"]default[\'"]', response_body, re.IGNORECASE)
                if match:
                    start_offset = response_info.getBodyOffset() + match.start()
                    end_offset = response_info.getBodyOffset() + match.end()
                    issues.append(self._create_issue_with_markers(baseRequestResponse, "Trusted Types: Check for 'Default' policy creation", 
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>A 'TrustedTypes.createPolicy' invocation was detected where the policy name is set to 'default'. Using the default "\
                                                 "policy weakens the protection offered by Trusted Types, as it allows any type of content to be considered trusted. "\
                                                 "This can lead to a security bypass and potential injection vulnerabilities.</p>",
                                                 "Firm", "Low", 
                                                 "Define specific and named policies that restrict which types of content are trusted. Use a policy provided by a "\
                                                 "common JavaScript framework such as DOMpurify or create your own policy.  Avoid setting Trusted Types policies to "\
                                                 "'default', noting that this may be required during transition towards using the Trusted Types security controls.",
                                                 start_offset, end_offset))

                # reduce false positives by checking the search term "trust:false" comes in with JS that attempts to create a Trusted Types policy
                if re.search(r'trustedTypes\.createPolicy\s*\(', response_body, re.IGNORECASE):
                    match = re.search(r'return\s+{.*?trust\s*:\s*false.*?}', response_body, re.IGNORECASE | re.DOTALL)
                    if match:
                        start_offset = response_info.getBodyOffset() + match.start()
                        end_offset = response_info.getBodyOffset() + match.end()
                        issues.append(self._create_issue_with_markers(baseRequestResponse, "Trusted Types: Policy returns untrusted data", 
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>A Trusted Types policy was found returning a data object with the 'trust' attribute explicitly set to 'false'. "\
                                                 "This can undermine the security model of Trusted Types, allowing untrusted data to be processed by the application, "\
                                                 "increasing the risk of content injection attacks.</p>",
                                                 "Firm", "Low", 
                                                 "Ensure that Trusted Types policies return sanitised and trusted data objects and that those objects have 'trust' "\
                                                 "marked as 'true'.",
                                                 start_offset, end_offset))

            if content_type and "text/html" in content_type:
                if re.search(r"require-trusted-types-for 'script'", response_body, re.IGNORECASE) is None:
                    issues.append(self._create_issue(baseRequestResponse, "Trusted Types: Missing 'require-trusted-types-for' directive in CSP",
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>The Content Security Policy (CSP) for this page is missing the \"require-trusted-types-for 'script'\" directive. "\
                                                 "This directive enforces that all scripts loaded on the page must comply with Trusted Types, providing an additional "\
                                                 "layer of protection against DOM-based Cross-Site Scripting (XSS) attacks.</p>",
                                                 "Certain", "Low", "Add the \"require-trusted-types-for 'script'\" directive to your CSP header."))

                if re.search(r"trusted-types .*", response_body, re.IGNORECASE) is None:
                    issues.append(self._create_issue(baseRequestResponse, "Trusted Types: Missing 'trusted-types' directive in CSP", 
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>The trusted-types directive is missing from the Content Security Policy (CSP). This directive specifies which "\
                                                 "Trusted Types policies are allowed in the page. Without this directive, any policy can be created, potentially "\
                                                 "weakening security by allowing unsafe operations.</p>",
                                                 "Certain", "Low", "Add a 'trusted-types' directive and configuration to your CSP header to specify allowed policies."))

                match = re.search(r"trusted-types .* allow-duplicates", response_body, re.IGNORECASE)
                if match:
                    start_offset = response_info.getBodyOffset() + match.start()
                    end_offset = response_info.getBodyOffset() + match.end()
                    issues.append(self._create_issue_with_markers(baseRequestResponse, "Trusted Types: Use of insecure 'allow-duplicates' Trusted Types directive",
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>The trusted-types directive includes the 'allow-duplicates' option. This allows the creation of multiple Trusted "\
                                                 "Types policies with the same name, which could lead to inconsistencies or unintended behaviour that "\
                                                 "weakens the application's security.</p>",
                                                 "Firm", "Low", "Remove 'allow-duplicates' from your Trusted Types directive to prevent duplicate policy names.",
                                                 start_offset, end_offset))

                match = re.search(r"trusted-types\s*:\s*([\'\"]?\s*[\'\"]?|default)\s*;?", response_body, re.IGNORECASE)
                if match:
                    start_offset = response_info.getBodyOffset() + match.start()
                    end_offset = response_info.getBodyOffset() + match.end()
                    issues.append(self._create_issue_with_markers(baseRequestResponse, "Trusted Types: use of default or blank policy", 
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>A 'TrustedTypes.createPolicy' invocation was detected where the policy name is set to 'default'. Using the default "\
                                                 "policy weakens the protection offered by Trusted Types, as it allows any type of content to be considered trusted. "\
                                                 "This can lead to a security bypass and potential injection vulnerabilities.</p>",
                                                 "Firm", "Low", 
                                                 "Avoid using the default policy in Trusted Types. Instead, define specific and named policies that restrict which "\
                                                 "types of content are trusted. For example, create a policy that properly sanitises input before treating it as trusted.",
                                                 start_offset, end_offset))

                match = re.search(r"trusted-types .* none", response_body, re.IGNORECASE)
                if match:
                    start_offset = response_info.getBodyOffset() + match.start()
                    end_offset = response_info.getBodyOffset() + match.end()
                    issues.append(self._create_issue_with_markers(baseRequestResponse, "Trusted Types: Actively disabled in CSP",
                                                 "<p>Trusted Types is a browser security feature that helps prevent Cross-Site Scripting (XSS) attacks by restricting "\
                                                 "the types of content that can be injected into the DOM, ensuring only trusted, sanitised content is used.</p>"\
                                                 "<p>The trusted-types directive includes the value 'none'. This disables Trusted Types protection entirely, allowing "\
                                                 "untrusted content to be treated as trusted.</p>"
                                                 "Certain", "Low", 
                                                 "Do not use 'none' in your Trusted Types directive. Instead develop a policy that correctly sanitises input in as "\
                                                 "constrained a manner as permitable for this application",
                                                 start_offset, end_offset))

        return issues

    def _create_issue(self, baseRequestResponse, name, detail, confidence, severity, remediation):
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        return CustomScanIssue(
            url, name, detail, baseRequestResponse, confidence, severity, remediation
        )

    def _create_issue_with_markers(self, baseRequestResponse, name, detail, confidence, severity, remediation, start_offset, end_offset):
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        markers = [(start_offset, end_offset)]
        return CustomScanIssueWithMarkers(
            url, name, detail, baseRequestResponse, confidence, severity, remediation, markers
        )

    def extensionUnloaded(self):
        print("Trusted Types Checker was unloaded")

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

class CustomScanIssue(IScanIssue):

    def __init__(self, url, name, detail, baseRequestResponse, confidence, severity, remediation):
        self._url = url
        self._name = name
        self._detail = detail
        self._confidence = confidence
        self._severity = severity
        self._httpMessages = [baseRequestResponse]
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpMessages[0].getHttpService()
