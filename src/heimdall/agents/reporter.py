# Will generate a report of the findings.

from __future__ import annotations

import os
import time
import math
import re  # Added for pattern matching in improved scoring algorithm
from datetime import timedelta
from typing import Any, Dict, List, Optional

from tools.llms import LLM

# Optional PDF generation libraries
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
except ImportError:  # reportlab may not be installed in the runtime
    canvas = None  # type: ignore


class ReporterAgent:
    """Generate a comprehensive, executive-ready report from the orchestration results.
    """

    def __init__(self, desc: str, api_type: str = "gemini", model_key: str = "gemini-2.5-pro-preview-05-06", 
                 reasoning: bool = True, temperature: float = 0.3) -> None:
        self.desc = desc
        self.api_type = api_type
        self.model_key = model_key
        self.reasoning = reasoning
        self.temperature = temperature
        self.llm = LLM(desc=desc)

        # in-memory caches
        self._findings: List[str] = []
        self._plans: List[Dict[str, Any]] = []
        self._network_logs: List[str] = []
        self._screenshots: List[str] = []
        # In-memory list of individual network requests (populated by orchestration layer)
        self._network_requests: List[Dict[str, Any]] = []
        
        # Cache last generated report sections so helper getters can expose them later
        self._last_stats: Dict[str, Any] = {}
        self._last_narrative: Dict[str, str] = {}
        # Caches for the new goal-specific sections
        self._last_testing_summary: List[Dict[str, str]] = []
        self._last_code_recs: List[Dict[str, str]] = []
        # Caches for conclusion & timeline (new goals)
        self._last_conclusion: Dict[str, Any] = {}
        self._last_timeline: List[Dict[str, Any]] = []


    def generate_report( self, findings: List[str], duration_seconds: float,
        total_endpoints: int, plans_executed: List[Dict[str, Any]], token_usage: int,
        network_logs: Optional[List[str]] = None, output_pdf: str = "security_audit_report.pdf",
    ) -> str:

        # 0)  gather from in-memory if arguments empty
        if not findings:
            findings = self._findings
        if not plans_executed:
            plans_executed = self._plans
        if network_logs is None:
            network_logs = self._network_logs

        # 1) Deterministic sections 
        score, risk_level = self._calculate_security_score(findings)
        overall_severity = self._determine_overall_severity(findings)
        total_issues = self._count_total_issues(findings)
        stats_section = self._build_stats_section( score, risk_level, overall_severity,
            duration_seconds, total_endpoints, total_issues, token_usage,
        )

        # 2) LLM powered narrative sections
        narrative_sections = self._generate_narrative_sections(findings, plans_executed)

        # 2.1) Structured conclusion & timeline (new goals)
        conclusion_summary = self._generate_conclusion_summary(
            stats_section,
            narrative_sections,
            findings,
        )
        timeline_items = self._build_implementation_timeline(conclusion_summary.get("next_steps", []))

        # 3) Assemble structured report object ---------------------------------
        network_summary = self.summarize_network_traffic()

        report_data: Dict[str, Any] = {
            "stats": stats_section,
            **narrative_sections,
            "conclusion_structured": conclusion_summary,
            "timeline_items": timeline_items,
            "findings_raw": findings,
            "plans": plans_executed,
            "network_logs": network_logs or [],
            "network_summary": network_summary,
            "screenshots": self._screenshots,
            # Goal-specific additions
            "testing_methods_summary": self.summarize_testing_methods(plans_executed),
            "codebase_recommendations": self.generate_codebase_recommendations(findings, plans_executed),
        }

        # 3.5) Cache sections for helper getters
        self._last_stats = stats_section
        self._last_narrative = narrative_sections
        self._last_testing_summary = report_data["testing_methods_summary"]
        self._last_code_recs = report_data["codebase_recommendations"]
        self._last_conclusion = conclusion_summary
        self._last_timeline = timeline_items

        # 4) Export to PDF (FALLBACK to .txt if PDF cannot be produced) --------
        try:
            if canvas is not None:
                self._export_pdf(report_data, output_pdf)
            else:
                # FALLBACK – dump as txt so user gets *something*
                print("[ReporterAgent] FALLBACK: ReportLab not available, generating text report instead")
                output_pdf = output_pdf.replace(".pdf", ".txt")
                with open(output_pdf, "w", encoding="utf-8") as fh:
                    fh.write(self._render_plaintext(report_data))
        except Exception as pdf_err:
            # FALLBACK: As a last resort – write plaintext
            print(f"[ReporterAgent] FALLBACK: PDF export failed ({pdf_err}), generating text report instead")
            fallback_path = output_pdf.replace(".pdf", "_fallback.txt")
            with open(fallback_path, "w", encoding="utf-8") as fh:
                fh.write(self._render_plaintext(report_data))
            output_pdf = fallback_path
            print(f"[ReporterAgent] FALLBACK: Text report saved to {fallback_path}")

        return os.path.abspath(output_pdf)

    # Helper functions
    def _call_llm(self, prompt: str, include_thoughts: bool = None) -> str:
        """Centralized LLM calling method that supports both gemini and fireworks APIs."""
        try:
            # Use reasoning parameter from instance if include_thoughts not specified
            if include_thoughts is None:
                include_thoughts = self.reasoning
                
            if self.api_type == "gemini":
                response = self.llm.gemini_reasoning_call(
                    prompt,
                    model=self.model_key,
                    temperature=self.temperature,
                    include_thoughts=include_thoughts
                )
                # Handle potential dict response from reasoning call
                if isinstance(response, dict):
                    return response.get('text', str(response))
                return response
            elif self.api_type == "fireworks":
                response = self.llm.fireworks_call(
                    prompt,
                    model_key=self.model_key,
                    reasoning=include_thoughts,
                    temperature=self.temperature
                )
                return response
            else:
                raise ValueError(f"Unsupported api_type: {self.api_type}. Use 'gemini' or 'fireworks'")
                
        except Exception as e:
            print(f"[ReporterAgent] LLM call failed: {str(e)}")
            raise


    @staticmethod
    def _calculate_security_score(findings: List[str]) -> tuple[int, str]:
        """Compute an overall security score following the OWASP Risk Rating
        Methodology (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology).
        """

        # --- BEGIN OWASP RISK RATING IMPLEMENTATION ---
        # The OWASP methodology calculates overall risk as a combination of
        # Likelihood and Impact where each dimension is first rated on a
        # 0-9 scale, reduced to Low/Medium/High buckets and finally looked up
        # in a 3×3 matrix to obtain a qualitative "severity" (Critical, High …).
        #
        # Because the raw penetration-test findings only contain limited
        # metadata, we approximate each OWASP factor as follows:
        #
        #   • Likelihood proxy  – the *exploit complexity* hints embedded in
        #     the finding text (e.g. "EXPERT-LEVEL", "ADVANCED", default).
        #       EXPERT            -> 1   (hard to exploit → low likelihood)
        #       ADVANCED / HIGH   -> 4   (medium likelihood)
        #       DEFAULT / unknown -> 7   (easy → high likelihood)
        #
        #   • Impact proxy – the *technical severity* (Critical/High/… emoji or
        #     keywords) optionally raised/lowered by an explicit business impact
        #     tag in the text ("CRITICAL BUSINESS IMPACT", etc).
        #       Severity :  Critical 9  | High 6 | Medium 4 | Low 1
        #       Business-impact tag (if present) overrides the technical one.
        #
        # The numeric scores are bucketed (0-2 = Low, 3-5 = Medium, 6-9 = High)
        # and then mapped through the OWASP matrix to obtain the final
        # *risk category* for the finding.
        #
        # That category is then translated into a penalty deducted from 100 to
        # yield the overall security score for the scan.
        #
        # ------------------------------------------------------------------
        
        base_score: float = 100.0

        # -------------------- Helper tables --------------------
        severity_numeric = {
            "critical": 9,
            "high": 6,
            "medium": 4,
            "low": 1,
        }

        # Exploit-complexity → likelihood numeric proxy
        complexity_numeric = {
            "expert": 1,   # hard → low likelihood
            "high": 4,     # advanced techniques
            "default": 7,  # easy / unknown → high likelihood
        }

        # OWASP likelihood / impact buckets
        def bucket(val: int) -> str:
            if val < 3:
                return "low"
            elif val < 6:
                return "medium"
            return "high"

        # OWASP severity matrix (Impact rows × Likelihood cols)
        owasp_matrix = {
            ("low", "low"): "note",
            ("medium", "low"): "low",
            ("high", "low"): "medium",
            ("low", "medium"): "low",
            ("medium", "medium"): "medium",
            ("high", "medium"): "high",
            ("low", "high"): "medium",
            ("medium", "high"): "high",
            ("high", "high"): "critical",
        }

        # Translate OWASP severity to numeric penalty
        severity_penalty = {
            "critical": 25.0,
            "high": 15.0,
            "medium": 10.0,
            "low": 5.0,
            "note": 1.0,
        }

        compliance_penalty = 5.0  # additive penalty for compliance risks

        total_penalty: float = 0.0

        for finding in findings:
            f_upper = finding.upper()

            # ---------------- Technical severity ---------------
            if "CRITICAL" in f_upper:
                tech_severity = "critical"
            elif "HIGH" in f_upper:
                tech_severity = "high"
            elif "MEDIUM" in f_upper:
                tech_severity = "medium"
            else:
                tech_severity = "low"

            # Override with explicit *BUSINESS IMPACT* tag if present
            if "CRITICAL BUSINESS IMPACT" in f_upper:
                impact_numeric = severity_numeric["critical"]
            elif "HIGH BUSINESS IMPACT" in f_upper:
                impact_numeric = severity_numeric["high"]
            elif "LOW BUSINESS IMPACT" in f_upper:
                impact_numeric = severity_numeric["low"]
            else:
                impact_numeric = severity_numeric[tech_severity]

            # ---------------- Likelihood (complexity proxy) -----
            if "EXPERT-LEVEL" in f_upper or "EXPERT" in f_upper:
                likelihood_numeric = complexity_numeric["expert"]
            elif ("ADVANCED" in f_upper) or (
                "HIGH" in f_upper and "COMPLEXITY" in f_upper
            ):
                likelihood_numeric = complexity_numeric["high"]
            else:
                likelihood_numeric = complexity_numeric["default"]

            # ---------------- Bucket → Severity ----------------
            impact_bucket = bucket(impact_numeric)
            likelihood_bucket = bucket(likelihood_numeric)
            owasp_severity = owasp_matrix[(impact_bucket, likelihood_bucket)]

            # ---------------- Penalty --------------------------
            penalty = severity_penalty[owasp_severity]
            if "COMPLIANCE RISK" in f_upper:
                penalty += compliance_penalty

            total_penalty += penalty

        # Cap penalty to avoid negatives and round to int for presentation
        score = max(int(round(base_score - total_penalty)), 0)

        # -------------------- Qualitative label ---------------
        if score >= 85:
            level = "Excellent"
        elif score >= 70:
            level = "Good"
        elif score >= 55:
            level = "Moderate"
        elif score >= 35:
            level = "Poor"
        else:
            level = "Critical"

        return score, level
        # --- END OWASP RISK RATING IMPLEMENTATION ---

    def _determine_overall_severity(self, findings: List[str]) -> str:
        
        findings_upper = [f.upper() for f in findings]
        if any(word in f for f in findings_upper for word in ("CRITICAL", "HIGH")):
            return "High"
        if any("MEDIUM" in f for f in findings_upper):
            return "Medium"
        return "Low"

    def _count_total_issues(self, findings: List[str]) -> int:
        """Return the total number of unique issues discovered."""
        return len(findings)

    def _build_stats_section( self, score: int, risk_level: str, severity: str, 
        duration_seconds: float, total_endpoints: int, issues_found: int, token_usage: int,
    ) -> Dict[str, Any]:
        duration_td = timedelta(seconds=int(duration_seconds))
        return {
            "security_score": score,
            "risk_level": risk_level,
            "overall_severity": severity,
            "scan_duration": str(duration_td),
            "endpoints_scanned": total_endpoints,
            "issues_found": issues_found,
            "token_usage": token_usage,
        }

    # ----------------------- LLM powered bits -----------------------------
    def _generate_narrative_sections(
        self,
        findings: List[str],
        plans_executed: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        try:
            findings_text = "\n".join(findings[:50])  # cap context length
            plans_text_lines: List[str] = []
            for p in plans_executed[:20]:
                plans_text_lines.append(f"• {p.get('title', 'Untitled')}: {p.get('description', '')[:120]}")
            plans_text = "\n".join(plans_text_lines)

            prompt = (
                "You are an experienced security lead writing an executive-level penetration test report. "
                "Given the findings below and the testing methods used, draft: \n"
                "1. A concise overview (<= 120 words)\n"
                "2. Key findings summary (bullet list, max 8 bullets)\n"
                "3. Strategic recommendations (bullet list, max 8)\n"
                "4. Conclusion & next steps (<= 100 words)\n\n"
                "=== FINDINGS ===\n" + findings_text + "\n\n=== TEST METHODS ===\n" + plans_text + "\n"
            )

            raw_text = self._call_llm(prompt)

            # Very lightweight post-processing – split into sections by numbered list
            overview = recommendations = conclusion = key_findings = ""
            for line in raw_text.splitlines():
                _l = line.strip()
                if _l.startswith("1."):
                    overview = _l[2:].strip()
                elif _l.startswith("2."):
                    key_findings = _l[2:].strip()
                elif _l.startswith("3."):
                    recommendations = _l[2:].strip()
                elif _l.startswith("4."):
                    conclusion = _l[2:].strip()

            return {
                "overview": overview or raw_text[:300],
                "key_findings": key_findings,
                "recommendations": recommendations,
                "conclusion": conclusion,
            }

        except Exception as err:
            print(f"[ReporterAgent] FALLBACK: LLM narrative generation failed: {err}")
            return {
                "overview": "FALLBACK: Unable to generate overview due to LLM error",
                "key_findings": "FALLBACK: Unable to generate key findings due to LLM error",
                "recommendations": "FALLBACK: Unable to generate recommendations due to LLM error",
                "conclusion": "FALLBACK: Unable to generate conclusion due to LLM error",
            }


    def summarize_testing_methods(self, plans_executed: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        if not plans_executed:
            return []

        methods: List[Dict[str, str]] = []
        for p in plans_executed:
            name = p.get("title", "Untitled Plan")
            desc_full = (p.get("description", "") or "").strip()
            summary = desc_full[:140] + ("…" if len(desc_full) > 140 else "")
            tools_libs = p.get("libraries") or p.get("technique") or "N/A"
            methods.append({
                "name": name,
                "summary": summary,
                "tools": tools_libs,
            })

        return methods


    def generate_codebase_recommendations(
        self,
        findings: List[str],
        plans_executed: List[Dict[str, Any]],
        max_recommendations: int = 10,
    ) -> List[Dict[str, str]]:
        """Use an LLM to suggest concrete improvements to the code-base.

        The assistant is instructed to output a JSON array where each object
        has the following keys: title, desc, implementation, effort_level,
        impact, time_to_implement, criticality.  We parse the JSON; if parsing
        fails we gracefully degrade by returning an empty list so that report
        generation never fails.
        """

        # Quickly short-circuit if we already generated and cached in this run
        if self._last_code_recs:
            return self._last_code_recs

        try:
            findings_context = "\n".join(findings[:50])
            plans_context = "\n".join([p.get("title", "Untitled") for p in plans_executed[:20]])

            prompt = (
                "You are a senior software architect reviewing a code-base that "
                "was just penetration-tested. Based on the security findings "
                "and the testing methods employed, suggest up to {n} high-impact "
                "improvements to the *code-base*. Each recommendation must be "
                "returned as a JSON object with these fields: title, desc, "
                "implementation, effort_level (Low/Medium/High), impact, "
                "time_to_implement (in person-days), criticality (Low/Medium/High/Critical). "
                "Respond ONLY with a JSON array, no additional text.\n\n"
                "=== SECURITY FINDINGS (truncated) ===\n" + findings_context + "\n\n"
                "=== TESTING METHODS ===\n" + plans_context + "\n"
            ).format(n=max_recommendations)

            raw_json = self._call_llm(prompt, include_thoughts=False)

            # Extract JSON array – the model might wrap it in markdown fences
            import json, re
            json_match = re.search(r"\[.*\]", raw_json, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON array found in LLM response")

            recommendations = json.loads(json_match.group(0))

            # Basic sanity-check – list[dict] with expected keys
            sanitized: List[Dict[str, str]] = []
            expected_keys = {"title", "desc", "implementation", "effort_level", "impact", "time_to_implement", "criticality"}
            for rec in recommendations:
                if not isinstance(rec, dict):
                    continue
                sanitized.append({k: str(rec.get(k, "")) for k in expected_keys})

            # Cache for later getters and return
            self._last_code_recs = sanitized[:max_recommendations]
            return self._last_code_recs

        except Exception as err:
            print(f"[ReporterAgent] FALLBACK: Failed to generate codebase recommendations: {err}")
            return []

    # ---------------- Public getters for new sections ----------------
    def testing_methods_summary(self) -> List[Dict[str, str]]:
        return self._last_testing_summary

    def codebase_recommendations(self) -> List[Dict[str, str]]:
        return self._last_code_recs

    # ----------------------- Export helpers -------------------------------

    def _export_pdf(self, report: Dict[str, Any], file_path: str) -> None:
        """Very simple PDF – can be styled later."""
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter
        line_height = 14
        margin = 40
        y = height - margin

        def write_line(text: str, _bold: bool = False):
            nonlocal y
            if y < margin:
                c.showPage()
                y = height - margin
            if _bold:
                c.setFont("Helvetica-Bold", 12)
            else:
                c.setFont("Helvetica", 11)
            c.drawString(margin, y, text)
            y -= line_height

        # Title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(margin, y, "Comprehensive Security Assessment Report")
        y -= line_height * 2

        # Stats
        write_line("=== Assessment Statistics ===", True)
        for k, v in report["stats"].items():
            write_line(f"{k.replace('_', ' ').title()}: {v}")
        y -= line_height

        # Overview & narrative sections
        write_line("=== Executive Overview ===", True)
        for line in self._wrap_text(report.get("overview", ""), 90):
            write_line(line)
        y -= line_height

        write_line("=== Key Findings ===", True)
        for bullet in report.get("key_findings", "").split("•"):
            bullet = bullet.strip(" -•\n")
            if bullet:
                write_line(f"• {bullet}")
        y -= line_height

        write_line("=== Recommendations ===", True)
        for bullet in report.get("recommendations", "").split("•"):
            bullet = bullet.strip(" -•\n")
            if bullet:
                write_line(f"• {bullet}")
        y -= line_height

        # Structured conclusion summary (new goal)
        if report.get("conclusion_structured"):
            cs = report["conclusion_structured"]
            write_line("=== Structured Conclusion Summary ===", True)
            write_line(f"Overall Risk: {cs.get('overall_risk')}")
            # Next steps
            if cs.get("next_steps"):
                write_line("Next Steps:")
                for step in cs["next_steps"]:
                    write_line(f" • {step}")
            # Strategic points
            if cs.get("strategic_points"):
                write_line("Strategic Points:")
                for sp in cs["strategic_points"]:
                    write_line(f" • {sp}")
            # Compliance snapshot
            comp = cs.get("compliance", {})
            if comp:
                write_line("Compliance Snapshot:")
                for k, v in comp.items():
                    write_line(f"   {k}: {v}")
            # Timeline note
            if cs.get("timeline_note"):
                write_line(f"Timeline Note: {cs.get('timeline_note')}")
            y -= line_height

        # Implementation timeline items (new goal)
        if report.get("timeline_items"):
            write_line("=== Implementation Timeline ===", True)
            for item in report["timeline_items"]:
                write_line(f"{item['sequence']}. ({item['time_range']}) {item['plan']}")
            y -= line_height

        # Testing methods summary (goal #1)
        if report.get("testing_methods_summary"):
            write_line("=== Testing Methods Used ===", True)
            for method in report["testing_methods_summary"]:
                write_line(f"• {method.get('name')}: {method.get('summary')}")
                write_line(f"   Tools/Libraries: {method.get('tools')}")
            y -= line_height

        # Codebase improvement recommendations (goal #2)
        if report.get("codebase_recommendations"):
            write_line("=== Codebase Improvement Recommendations ===", True)
            for rec in report["codebase_recommendations"]:
                title = rec.get("title", "Recommendation")
                write_line(f"• {title} – Impact: {rec.get('impact')} – Effort: {rec.get('effort_level')}")
                for line in self._wrap_text(rec.get("desc", ""), 90):
                    write_line(f"   {line}")
                impl = rec.get("implementation", "")
                if impl:
                    impl_lines = self._wrap_text("Implementation: " + impl, 90)
                    for line in impl_lines:
                        write_line(f"   {line}")
            y -= line_height

        # Findings table (truncated with metadata)
        write_line("=== Top Vulnerabilities (metadata) ===", True)
        header = ["Severity", "Impact", "Complexity", "Compliance", "Finding"]
        write_line(" | ".join(header), True)
        for f in report["findings_raw"][:15]:
            meta = self._parse_finding_metadata(f)
            row = f"{meta['severity']} | {meta['impact']} | {meta['complexity']} | {meta['compliance']} | {f[:60]}"
            for line in self._wrap_text(row, 100):
                write_line(line)
        y -= line_height

        # Testing methods / plans
        plans = report.get("plans", [])
        if plans:
            write_line("=== Testing Methods Used ===", True)
            for p in plans:
                title = p.get("title", "Untitled")
                desc = (p.get("description", "") or "")[:120]
                lib = p.get("libraries", p.get("technique")) or ""
                write_line(f"• {title}: {desc}")
                if lib:
                    write_line(f"   Technique/Libraries: {lib}")
            y -= line_height

        # Network log excerpts
        logs = report.get("network_logs", [])
        if logs:
            write_line("=== Network Traffic (first 20 lines) ===", True)
            for log in logs[:20]:
                for line in self._wrap_text(log, 100):
                    write_line(line)
            y -= line_height

        # Network traffic summary (aggregated)
        traffic_summary = report.get("network_summary", [])
        if traffic_summary:
            write_line("=== Network Traffic Summary ===", True)
            header = ["Endpoint", "Method", "Total", "2xx", "3xx", "4xx", "5xx"]
            write_line(" | ".join(header), True)
            for row in traffic_summary:
                summary_line = f"{row['endpoint_path']} | {row['http_method']} | {row['total_requests']} | {row['status_2xx']} | {row['status_3xx']} | {row['status_4xx']} | {row['status_5xx']}"
                for line in self._wrap_text(summary_line, 100):
                    write_line(line)
            y -= line_height

        # Include screenshots if any (from recorded list first)
        screenshots = report.get("screenshots", []) or self._screenshots
        if not screenshots:
            # FALLBACK: Look for screenshots in current directory
            screenshots = [f for f in os.listdir(".") if f.lower().endswith((".png", ".jpg", ".jpeg"))]
        screenshots = screenshots[:5]
        if screenshots:
            write_line("=== Evidence Screenshots (preview) ===", True)
            for img_path in screenshots:
                try:
                    img = ImageReader(img_path)
                    iw, ih = img.getSize()
                    aspect = ih / float(iw)
                    display_width = width - 2 * margin
                    display_height = display_width * aspect
                    if y - display_height < margin:
                        c.showPage()
                        y = height - margin
                    c.drawImage(img, margin, y - display_height, width=display_width, height=display_height)
                    y -= display_height + line_height
                except Exception:
                    # FALLBACK: Skip problematic images silently
                    continue

        c.save()

    @staticmethod
    def _wrap_text(text: str, width: int) -> List[str]:
        words = text.split()
        lines: List[str] = []
        current = ""
        for w in words:
            if len(current) + len(w) + 1 > width:
                lines.append(current)
                current = w
            else:
                current += (" " if current else "") + w
        if current:
            lines.append(current)
        return lines

    def _render_plaintext(self, report: Dict[str, Any]) -> str:
        out_lines: List[str] = []
        out_lines.append("Comprehensive Security Assessment Report")
        out_lines.append("=" * 60)
        out_lines.append("\n[Statistics]")
        for k, v in report["stats"].items():
            out_lines.append(f"  {k}: {v}")
        out_lines.append("\n[Overview]\n" + report.get("overview", "N/A"))
        out_lines.append("\n[Key Findings]\n" + report.get("key_findings", "N/A"))
        out_lines.append("\n[Recommendations]\n" + report.get("recommendations", "N/A"))
        out_lines.append("\n[Conclusion]\n" + report.get("conclusion", "N/A"))
        out_lines.append("\n[Findings]\n" + "\n".join(report["findings_raw"]))

        # Plans
        if report.get("plans"):
            out_lines.append("\n[Testing Methods]")
            for p in report["plans"]:
                title = p.get("title", "Untitled")
                desc = (p.get("description", "") or "")[:120]
                libs = p.get("libraries", p.get("technique")) or ""
                out_lines.append(f"  • {title}: {desc}")
                if libs:
                    out_lines.append(f"    Technique/Libraries: {libs}")

        # Network logs (first 20)
        if report.get("network_logs"):
            out_lines.append("\n[Network Traffic – first 20 lines]")
            out_lines.extend(report["network_logs"][:20])

        # Screenshots list
        if report.get("screenshots"):
            out_lines.append("\n[Evidence Screenshots]")
            for path in report["screenshots"][:5]:
                out_lines.append(f"  - {path}")

        # Testing methods summary
        if report.get("testing_methods_summary"):
            out_lines.append("\n[Testing Methods Used]")
            for m in report["testing_methods_summary"]:
                out_lines.append(f"  • {m.get('name')}: {m.get('summary')} (Tools: {m.get('tools')})")

        # Codebase improvement recommendations
        if report.get("codebase_recommendations"):
            out_lines.append("\n[Codebase Improvement Recommendations]")
            for rec in report["codebase_recommendations"]:
                out_lines.append(f"  • {rec.get('title')} – {rec.get('desc')} (Impact: {rec.get('impact')}, Effort: {rec.get('effort_level')}, Time: {rec.get('time_to_implement')} days, Criticality: {rec.get('criticality')})")

        # Structured conclusion summary
        if report.get("conclusion_structured"):
            cs = report["conclusion_structured"]
            out_lines.append("\n[Structured Conclusion Summary]")
            out_lines.append(f"Overall Risk: {cs.get('overall_risk')}")
            if cs.get("next_steps"):
                out_lines.append("Next Steps:")
                for step in cs["next_steps"]:
                    out_lines.append(f"  - {step}")
            if cs.get("strategic_points"):
                out_lines.append("Strategic Points:")
                for sp in cs["strategic_points"]:
                    out_lines.append(f"  - {sp}")
            comp = cs.get("compliance", {})
            if comp:
                out_lines.append("Compliance Snapshot:")
                for k, v in comp.items():
                    out_lines.append(f"  {k}: {v}")
            if cs.get("timeline_note"):
                out_lines.append(f"Timeline Note: {cs.get('timeline_note')}")

        # Timeline items
        if report.get("timeline_items"):
            out_lines.append("\n[Implementation Timeline]")
            for item in report["timeline_items"]:
                out_lines.append(f"  {item['sequence']}. ({item['time_range']}) {item['plan']}")

        return "\n".join(out_lines)

    # ------------------------------------------------------------------
    # Finding metadata helper (severity / business impact / complexity / compliance)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_finding_metadata(finding: str) -> Dict[str, str]:
        """Derive structured metadata tags from a raw finding string the same
        way _calculate_security_score does, so that we can display them in
        tabular form inside the final report."""

        f_upper = finding.upper()

        # ---------- Severity ------------
        if "CRITICAL" in f_upper:
            severity = "Critical"
        elif "HIGH" in f_upper:
            severity = "High"
        elif "MEDIUM" in f_upper:
            severity = "Medium"
        else:
            severity = "Low"

        # ---------- Business impact -----
        if re.search(r"CRITICAL\s+BUSINESS\s+IMPACT", f_upper):
            impact = "Critical"
        elif re.search(r"HIGH\s+BUSINESS\s+IMPACT", f_upper):
            impact = "High"
        elif re.search(r"LOW\s+BUSINESS\s+IMPACT", f_upper):
            impact = "Low"
        else:
            impact = "Medium"

        # ---------- Complexity ----------
        if "EXPERT-LEVEL EXPLOITATION REQUIRED" in f_upper or "EXPERT" in f_upper:
            complexity = "Expert"
        elif "ADVANCED TECHNIQUES" in f_upper or ("HIGH" in f_upper and "COMPLEXITY" in f_upper):
            complexity = "High"
        else:
            complexity = "Default"

        # ---------- Compliance ----------
        compliance = "Yes" if "COMPLIANCE RISK" in f_upper else "No"

        return {
            "severity": severity,
            "impact": impact,
            "complexity": complexity,
            "compliance": compliance,
        }

    def overall_key_findings(self) -> List[Dict[str, str]]:

        if not self._last_narrative:
            return []
        bullets_raw = self._last_narrative.get("key_findings", "")
        findings: List[Dict[str, str]] = []
        for raw in bullets_raw.split("•"):
            line = raw.strip(" -\n\r\t")
            if not line:
                continue
            # Attempt to split into title / description by common separators
            if ":" in line:
                title, desc = line.split(":", 1)
            elif "-" in line:
                title, desc = line.split("-", 1)
            else:
                title, desc = line[:60], line
            findings.append({"title": title.strip(), "description": desc.strip()})
        return findings

    def summary_overview(self) -> str:
        return self._last_narrative.get("overview", "") if self._last_narrative else ""

    def total_endpoints_scanned(self) -> int:
        return int(self._last_stats.get("endpoints_scanned", 0)) if self._last_stats else 0

    # ------------------------------------------------------------------
    # New goal – Structured conclusion summary
    # ------------------------------------------------------------------
    def _generate_conclusion_summary( self, stats_section: Dict[str, Any],
        narrative_sections: Dict[str, str], findings: List[str],
    ) -> Dict[str, Any]:


        if self._last_conclusion:
            return self._last_conclusion

        try:
            overall_risk = stats_section.get("risk_level", "Moderate")
            findings_text = "\n".join(findings[:50])
            recommendations_text = narrative_sections.get("recommendations", "")

            prompt = (
                "You are a CISO drafting the executive conclusion of a security "
                "assessment. Using the security score ({score}) and risk level "
                "({risk}), summarise the overall risk outlook. Provide concrete "
                "next remediation steps (max 8) and strategic security points "
                "for leadership (max 8). Give a short compliance snapshot for "
                "OWASP, PCI-DSS, GDPR and SOX. Finally include a concise timeline "
                "note (<= 40 words). Respond ONLY with a JSON object using the "
                "exact keys: overall_risk, next_steps, strategic_points, "
                "compliance, timeline_note. Do not wrap in markdown.\n\n"
                "=== KEY FINDINGS (truncated) ===\n" + findings_text + "\n\n"
                "=== HIGH-LEVEL RECOMMENDATIONS ===\n" + recommendations_text + "\n"
            ).format(score=stats_section.get("security_score"), risk=overall_risk)

            raw_json = self._call_llm(prompt, include_thoughts=False)

            import json, re
            json_match = re.search(r"\{.*\}", raw_json, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON object found in LLM response")

            conclusion_data = json.loads(json_match.group(0))

            # Basic sanity – ensure mandatory keys exist
            required_keys = {"overall_risk", "next_steps", "strategic_points", "compliance", "timeline_note"}
            for k in required_keys:
                if k not in conclusion_data:
                    conclusion_data[k] = "" if k != "next_steps" and k != "strategic_points" else []

            return conclusion_data

        except Exception as err:
            print(f"[ReporterAgent] FALLBACK: Failed to generate structured conclusion: {err}")
            # FALLBACK: Simple structure
            return {
                "overall_risk": stats_section.get("risk_level", "Moderate"),
                "next_steps": [s.strip() for s in narrative_sections.get("recommendations", "").split("•") if s.strip()][:4],
                "strategic_points": [
                    "FALLBACK: Establish secure coding standards",
                    "FALLBACK: Quarterly penetration testing",
                    "FALLBACK: Continuous security training for developers",
                    "FALLBACK: Implement security review for all code changes",
                ],
                "compliance": {
                    "OWASP": "FALLBACK: Needs review" if stats_section.get("risk_level") in ("Poor", "Critical") else "FALLBACK: Compliant",
                    "PCI-DSS": "FALLBACK: Partially compliant",
                    "GDPR": "FALLBACK: Compliant",
                    "SOX": "FALLBACK: Needs review",
                },
                "timeline_note": "FALLBACK: Critical fixes scheduled for the next sprint.",
            }

    # ------------------------------------------------------------------
    # New goal – Implementation timeline overview
    # ------------------------------------------------------------------
    @staticmethod
    def _build_implementation_timeline(next_steps: List[str]) -> List[Dict[str, Any]]:
        """Create a simple sequential timeline for executing the provided next
        steps. The first item is scheduled for week 1-2, second 2-3, etc."""

        timeline: List[Dict[str, Any]] = []
        if not next_steps:
            return timeline

        for idx, step in enumerate(next_steps, 1):
            start = idx
            end = idx + 1
            timeline.append({
                "sequence": idx,
                "time_range": f"{start}-{end} weeks",
                "plan": step,
            })

        return timeline

    # ---------------- Public getters for new sections ----------------
    def conclusion_summary(self) -> Dict[str, Any]:
        return self._last_conclusion

    def implementation_timeline(self) -> List[Dict[str, Any]]:
        return self._last_timeline

    # ---------------- incremental API ---------------
    def add_finding(self, finding: str):
        # Avoid duplicate findings which would skew scoring
        if finding not in self._findings:
            self._findings.append(finding)

    def add_plan(self, plan: Dict[str, Any]):
        if plan not in self._plans:
            self._plans.append(plan)

    def add_network_log(self, log: str):
        if log not in self._network_logs:
            self._network_logs.append(log)

    def add_screenshot(self, path: str):
        if path not in self._screenshots:
            self._screenshots.append(path)

    # ---------------- Network request capture -----------------
    def add_network_request(self, endpoint_path: str, http_method: str, status_code: int):
        """Record a single network request/response tuple so we can later
        aggregate detailed traffic statistics (per endpoint, method, status-class counts)."""

        self._network_requests.append(
            {
                "endpoint_path": endpoint_path,
                "http_method": http_method.upper(),
                "status_code": int(status_code),
            }
        )

    # ---------------- Traffic summarisation -------------------
    def summarize_network_traffic(self) -> List[Dict[str, Any]]:
        """Return aggregated network traffic statistics grouped by (endpoint, method).

        Example output:
            [
              {
                "endpoint_path": "/api/login/",
                "http_method": "POST",
                "total_requests": 320,
                "status_2xx": 250,
                "status_3xx": 0,
                "status_4xx": 60,
                "status_5xx": 10,
              },
              ...
            ]
        """

        aggregate: Dict[tuple[str, str], Dict[str, Any]] = {}

        for req in self._network_requests:
            key = (req["endpoint_path"], req["http_method"])
            if key not in aggregate:
                aggregate[key] = {
                    "endpoint_path": req["endpoint_path"],
                    "http_method": req["http_method"],
                    "total_requests": 0,
                    "status_2xx": 0,
                    "status_3xx": 0,
                    "status_4xx": 0,
                    "status_5xx": 0,
                }

            entry = aggregate[key]
            entry["total_requests"] += 1

            status = int(req["status_code"])
            if 200 <= status < 300:
                entry["status_2xx"] += 1
            elif 300 <= status < 400:
                entry["status_3xx"] += 1
            elif 400 <= status < 500:
                entry["status_4xx"] += 1
            elif 500 <= status < 600:
                entry["status_5xx"] += 1

        return list(aggregate.values())

    # ---------------- lifecycle -------------------
    def close(self):
        # No cleanup needed for in-memory storage
        pass








