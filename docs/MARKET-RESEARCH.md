> Market research produced 2026-11-20 via TinyFish deep research (51 sources).
> Figures are triangulated and explicitly uncertain where the report says so.
> Read section 6.3 (confidence calibration) before quoting any number.

# Verifiable AI Evaluation Infrastructure: Market Research & Revenue Model

## Executive Summary

A startup selling tamper-evident, cryptographically signed audit logs and attestations proving that AI safety evaluations were actually run occupies a narrow but structurally important white space at the intersection of three converging forces: (1) specific, enforceable regulatory obligations that require *evidence records* — not merely assertions — of AI testing; (2) a competitive landscape where no major vendor currently offers cryptographic verifiability as a core product; and (3) a set of well-validated analogous markets (software supply chain, SOC 2 automation, clinical trial audit trails) that have proven the "trust infrastructure" business model at scale.

**Budget is real today** — not in two to three years — among AI labs facing EU AI Act GPAI obligations (in force since August 2, 2025 [2]), enterprises in BFSI, healthcare and insurance facing imminent regulator examinations, and government procurement. The window for category creation is 18–36 months before incumbents (Vanta, Credo AI, IBM watsonx.governance) add "good enough" cryptographic logging as a feature bundle.

**The revenue model analog is Chainguard / Vanta, not a consulting firm.** Open-source the verifier to establish trust and ecosystem lock-in; monetize the managed witness infrastructure, enterprise SLA tier, and regulatory-ready report generation. A realistic path to $1M ARR requires closing 10–15 enterprise customers at $60K–$100K ACV within 12–18 months of launch, targeting BFSI and AI lab personas with active compliance deadlines.

**TAM is not yet large but growing rapidly.** The directly addressable market (AI governance platforms + AI assurance services + AI red-teaming) totals roughly $2.5B in 2026 and is projected to grow to $30B+ by 2034, with the cryptographic evidence layer a cross-cutting enabling technology for all three.

---

## 1. WHO BUYS THIS: Buyer Personas, Budget Owners, and Timing

### 1.1 Persona Map

| Persona | Budget Owner | Urgency | Active Budget Today? | Evidence |
|---|---|---|---|---|
| AI lab / frontier model provider (OpenAI, Anthropic, Google DeepMind, Mistral, etc.) | CISO + Head of Safety | High: EU AI Act Art. 55 in force since Aug 2025 [31] | **Yes** | GPAI adversarial testing & documentation obligations live [30][31] |
| Enterprise deployer: BFSI (banks, asset managers, insurers) | CRO / Chief Model Risk Officer | High: OCC updated MRM guidance 2026 [38], NAIC Bulletin 25-state adoption [39] | **Yes** | Pre-deployment fairness testing results requested by examiners today [39] |
| Enterprise deployer: Healthcare | CISO + CCO | Medium-High: HIPAA audit controls apply [16], high-risk AI Act deadline Dec 2027 [28] | **Yes, early adopters** | HIPAA 45 CFR 164.312(b) requires mechanisms to record and examine activity [16] |
| Enterprise deployer: Insurance (as AI user, not insurer) | CRO / Chief Actuary | Medium: NAIC Bulletin adopted in 25 states as of July 2026 [39] | **Yes** | Examiners request pre-deployment testing results, monitoring logs [39] |
| AI assurance / audit firms (KPMG, BSI, Big Four, specialist firms) | Partner / Practice Lead | Medium: Building service lines around ISO/IEC 42001 and EU AI Act [8] | **Yes, as infrastructure** | KPMG added AI assurance suite Sept 2025 [8]; BSI issued 50th ISO 42001 cert Oct 2026 [8] |
| AI risk insurers (Munich Re aiSure, specialty lines) | Underwriting / Actuarial | Medium: Pricing AI risk without data is the core problem [35][37] | **Emerging** | Munich Re aiSure triggered by performance errors, pricing is bespoke [36] |
| Government / defense procurement | Program managers / CIOs | Medium: US AI Action Plan directs frontier model evaluation [27]; EU AI Act public authority deadline 2030 [2] | **Selective, slow cycle** | Singapore, UAE, Saudi Arabia all building national AI testing programs [8][12] |
| Colorado / Texas / NYC-regulated HR & lending deployers | General Counsel + CHRO | Medium: NYC LL 144 bias audits required [9], Texas TRAIGA in force Jan 2026 [9] | **Yes** | NYC LL 144 requires bias audit within one year before use [9] |

### 1.2 Budget Timing: Today vs. 2–3 Years Out

**Budget active today (2026):**

The clearest immediately addressable buyers are (a) frontier AI labs and GPAI model providers, (b) BFSI enterprises, and (c) AI audit firms building service infrastructure. The regulatory logic is unambiguous: EU AI Act Article 55 obligations for systemic-risk GPAI providers have been in force since August 2, 2025 [31], requiring providers to conduct and *document* adversarial testing. The AI Office sent formal requests for information to more than thirty AI companies in August–September 2026, explicitly asking whether independent external evaluators assessed their models [44]. This is the earliest form of enforcement pressure, and it creates immediate demand for defensible, third-party-verifiable evidence records. BFSI is equally active: OCC updated model risk management guidance in 2026 [38], and state examiners under the NAIC Model Bulletin (adopted in 25 states by July 2026 [39]) are actively requesting pre-deployment fairness testing results and monitoring logs.

Credo AI reported 2× year-over-year revenue growth and 150% growth in enterprise customers in 2025 [24], and noted that "budgets shifted from exploratory spend to core operational infrastructure" — a signal that BFSI and healthcare enterprises are committing real procurement dollars. Gartner estimates AI governance spending at $492M in 2026 [1], and AI assurance services at $680M in 2025 growing to $11.8B by 2034 [8].

**Budget 2–3 years out (2027–2028):**

High-risk AI system deployers under EU AI Act Annex III (employment, education, biometrics, essential services) face a December 2, 2027 deadline following the Digital Omnibus deferral [8][11]. This cohort — HR software vendors, credit scoring systems, medical device AI — represents a much larger population with less immediate urgency but locked-in future demand. Healthcare AI, projected at 39.9% CAGR in AI governance [7], and government procurement (EU public authority deadline: August 2, 2030 [2]) are 2–3 year stories.

**The insurance buyer is a 3–5 year story with near-term pilot opportunity.** Over 90% of AI-related risks currently fall under "Silent AI" in insurance policies [37], and more than 60 P&C insurers filed for AI exclusions in 2026 [35]. Insurers cannot currently price AI risk because they lack data on insureds' AI usage [35]. A startup that provides insurers with verified evidence of evaluation rigor — essentially an underwriting data feed — could become a valuable intermediary. However, the market infrastructure for standalone AI insurance products is still forming. Munich Re's aiSure covers AI performance failures but prices bespoke [36], and AI insurance premiums are only projected to reach $4.8B by 2032 [21]. Treat this as a strategic channel partnership opportunity at year 2–3, not a launch-day buyer.

---

## 2. REGULATORY DRIVERS: Specific Obligations to Produce Verifiable Evidence

The critical analytical distinction is between regulations that require *having* a risk management process (most of them) versus regulations that require *producing documented, verifiable evidence* that specific tests were actually conducted and that records cannot be retrospectively falsified (fewer, but growing). The latter creates the structural need for this product.

### 2.1 EU AI Act: The Strongest Driver

**GPAI Model Obligations (Articles 53 and 55) — in force August 2, 2025 [2][30][31]:**

Article 53 requires GPAI providers to draw up and keep up-to-date technical documentation including "the results of its evaluation" and to provide it to the AI Office upon request [30]. The Commission may adopt delegated acts specifying "measurement and calculation methodologies with a view to allowing for comparable and *verifiable* documentation" [30] — the word "verifiable" is used in the statute itself.

Article 55, applicable to systemic-risk GPAI models (those above 10^25 FLOP [44]), goes further: providers must "perform model evaluation in accordance with standardised protocols and tools reflecting the state of the art, **including conducting and documenting adversarial testing** of the model with a view to identifying and mitigating systemic risks" [31]. The italics reflect the statutory language. Serious incidents must be tracked, documented, and reported without undue delay [31].

The GPAI Code of Practice (published July 10, 2025 [45]) operationalizes this with granular evidence requirements:
- Safety and Security Model Reports must be submitted *prior to release* [48]
- Documented information must be "controlled for quality and integrity, retained as evidence of compliance with obligations in the AI Act, and **protected from unintended alterations**" [49] — this is precisely the tamper-evident requirement
- Detailed records of safety and risk management activities must be kept for a minimum of ten years [48]
- Serious incident reports must be retained for at least five years [48]
- Signatories must provide independent external evaluators with access to models and publish transparent evaluator selection standards [48]
- The Model Report must include five randomly selected input/output samples from each relevant model evaluation "to support independent interpretation" [48]
- Framework evaluations must be conducted at minimum annually [48]

**High-Risk AI Systems (Articles 9, 11, 12, 19, 26, 32, Annex IV):**

Article 9 requires a risk management system to be "established, implemented, **documented** and maintained" [3]. High-risk AI systems must be tested against "prior defined metrics and probabilistic thresholds" and testing must be carried out "in any event, prior to their being placed on the market" [3].

Annex IV requires technical documentation to include "test logs and **all test reports dated and signed by the responsible persons**" [32]. The requirement for dated and signed test reports is the most direct legal hook for cryptographic timestamping and signing infrastructure.

Article 12 requires high-risk AI systems to allow "automatic recording of events (logs) over the lifetime of the system" [17][28]. Article 19 and Article 26(6) each set a minimum six-month log retention obligation for providers and deployers respectively [28]. Logs must support identification of risk situations, post-market monitoring, and deployers' monitoring [28].

The Digital Omnibus (Regulation (EU) 2026/1744) deferred Annex III standalone high-risk system obligations from August 2, 2026 to December 2, 2027 [8][11], giving enterprises more runway but not changing the fundamental evidentiary requirements.

**Timeline summary:**

| Obligation | Applies to | Operative Date |
|---|---|---|
| GPAI documentation & adversarial testing | Systemic-risk GPAI providers | August 2, 2025 [2][31] |
| AI Office enforcement (requests for info, fines) | All GPAI providers | August 2, 2026 [48] |
| Existing GPAI models compliance | Pre-Aug 2025 models | August 2, 2027 [2][21] |
| High-risk Annex III standalone systems | High-risk deployers/providers | December 2, 2027 [8][11] |
| High-risk Annex I product-embedded systems | Regulated product AI | August 2, 2028 [11][44] |
| Public authority AI systems | EU public authorities | August 2, 2030 [2] |

### 2.2 US Federal: Softer but Directionally Consistent

**NIST AI RMF:** Provides the GOVERN, MAP, MEASURE, MANAGE framework. NIST AI RMF and the NCCoE AI agent identity framework "expect action lineage records (Pillar 3) that support post-hoc investigation" [16]. However, the US AI Action Plan (July 2025) directs NIST to revise the AI RMF and signals a generally lighter regulatory posture federally [27]. The US federal regulatory environment is not creating hard legal mandates to produce tamper-evident evidence today; it is creating soft best-practice frameworks.

**OCC Model Risk Management Guidance (2026):** Updated guidance for OCC-supervised institutions, expected to be most relevant to banks with over $30 billion in assets [38]. Notably, generative AI and agentic AI models are explicitly *excluded from scope* of this guidance "because they are novel and rapidly evolving" [38], with a future request for information planned. This creates a temporary gap but also signals that specific guidance on AI model testing evidence for banks is coming.

**NAIC Model Bulletin on AI (adopted December 4, 2023, 25 states adopted by July 2026 [39]):** Requires insurers to document how AI systems are used, assess for bias, and maintain audit rights. State examiners are specifically expected to request "pre-deployment fairness testing results" and "ongoing monitoring logs" [39]. This is a direct evidence-of-testing requirement.

**FSB Sound Practices for Financial Institutions (2026 consultation [50]):** Sets out twelve sound practices, including strong governance and risk management. Internationally active banks and large trading firms are the primary target. Not a mandate, but signals the direction of international financial regulatory expectations.

### 2.3 US State Laws: Specific Evidence Obligations

**NYC Local Law 144:** Requires a bias audit "within one year before use" of automated employment decision tools, with public audit information and candidate notice [9]. The audit must be independent, creating a third-party evidence chain requirement.

**Texas TRAIGA (in force January 1, 2026):** Penalties up to $200,000 per uncurable violation [9]. Requires documentation but does not specifically mandate tamper-evident evidence; compliance teams will want defensible records.

**Colorado SB 26-189 (effective January 1, 2027):** Requires developers to give deployers technical documentation; deployers must give consumers plain-language explanations after adverse outcomes [9]. Creates a documentation trail that benefits from verifiability.

**California SB 53:** Large frontier developers must publish a framework describing how they apply national and international standards; critical safety incidents are reportable [9]. Signed, timestamped evidence of evaluations directly supports this.

**California SB 1119:** Requires independent audits of certain chatbots for child safety compliance [22]. Illinois AI Safety Measures Act (SB 315): Obligates large frontier developers to obtain third-party audits of their compliance [22]. New York RAISE Act (S8828/A9449): Requires frontier developers to publish transparency reports including descriptions of how third-party evaluators were involved [22].

**The key legal hook:** The EU AI Act's Annex IV requirement for "test logs and all test reports dated and signed by the responsible persons" [32], combined with the Code of Practice requirement that documentation be "protected from unintended alterations" [49], is the most specific statutory basis for cryptographic signing and tamper-evidence. No other regulation currently has language this precise, but the NAIC examiner expectations for "pre-deployment fairness testing results" [39] and FSB sound practices create functional equivalents in financial services.

### 2.4 Sector-Specific Regulatory Hooks

**Healthcare:** HIPAA audit controls at 45 CFR 164.312(b) require mechanisms to record and examine activity in information systems containing ePHI [16]. AI systems processing health data must maintain these records. Fannie Mae LL-2026-04 reportedly requires audit trails permitting reconstruction of AI-assisted decisions [16] — though this is a reported claim from a lower-quality source and should be independently verified.

**Financial services:** DORA (EU) ICT incident reporting requires firms to reconstruct incidents from records that "hold up in supervisory dialogue" [16] — a functional tamper-evidence requirement.

---

## 3. COMPETITIVE LANDSCAPE

### 3.1 AI Evaluation and Observability Vendors

None of the major AI evaluation and observability platforms currently offer cryptographic verifiability or tamper-evident audit trails as a core product feature. The landscape:

**LangSmith, Braintrust, Arize, Weights & Biases, Galileo, Humanloop:** These are logging, tracing, and evaluation platforms focused on developer productivity — debugging prompts, tracking model performance, running evals. Braintrust raised $80M Series B in February 2026 [12] and positions itself as "an observability layer for production AI." Langfuse explicitly states that "no tool makes a system compliant with the EU AI Act" and that it "helps you produce, retain, and review logs and evaluation records" [28] — an honest acknowledgment that it provides inputs to compliance, not compliance itself. None of these vendors have announced cryptographic signing or tamper-evident chaining of evaluation records.

**Patronus AI, Galtea:** Evaluation-focused platforms. Galtea's platform offers "traces, version comparisons, human reviews, CI/CD evaluation gates, and production monitors" and claims to provide "evaluation and monitoring data and traceability to support evidence requirements" [29]. However, Galtea's own caveat is clear: "Evaluation reports and traces do not by themselves establish EU AI Act compliance" [29]. No cryptographic attestation layer is described.

**Openlayer:** Claims to "maintain versioned audit trails and block model promotion when fairness thresholds are not met, producing the evidentiary records state regulators inspect" [39]. This is the closest to a verifiable evidence claim among eval vendors, but the product is described as maintaining versioned audit trails (database-level versioning), not cryptographically signed, externally verifiable attestations.

### 3.2 AI Red-Teaming Vendors

Pricing is uniformly undisclosed — every major vendor routes to a demo [40]. HiddenLayer's AWS Marketplace listing shows a $5,000,000/year contract dimension without defining the unit [20]. Prisma AIRS (incorporating former Protect AI) is priced per billion monthly tokens, with a $4,353/year AWS listing for a Prisma AIRS API contract without defining call volume [20]. PromptFoo is free/open-source (MIT license) with an enterprise tier [18].

**Cryptographic verifiability gap:** The most authoritative secondary assessment is unambiguous: "None of the compared red-teaming tools is described as offering cryptographic or tamper-evident audit trails for test evidence" [18]. HiddenLayer's materials do not map features to the EU AI Act or ISO/IEC 42001 [20]. Robust Intelligence was acquired by Cisco in 2024 and is being consolidated into Cisco AI Defense [18]. Haize Labs generates revenue via a services model to foundation model providers and a SaaS approach [23] — there is no indication of evidence attestation features.

**Key gap:** Red-teaming vendors produce findings; they do not produce cryptographically verifiable receipts that an independent party can verify to confirm the test was actually run as described. This is precisely the white space.

### 3.3 AI Governance and Compliance Platforms

**Credo AI:** The most feature-complete AI governance platform in this analysis. Credo AI *does* claim "tamper-evident logging of governance events (approvals, model changes, policy decisions) required by EU AI Act Article 12" and "automated hashing and retention of evidence (model cards, test results, approvals) for audit" [10]. It also markets LLM red-teaming capability [10]. However: Credo AI does not disclose pricing [10]; does not describe a third-party verifiable receipt system where an external party can independently verify that a test was run; and its tamper-evident logging appears to be a feature within its governance platform rather than standalone cryptographic infrastructure. With 2× YoY revenue growth in 2025 [24] and Forrester Wave Leader recognition, Credo AI is the most direct partial competitor.

**Vanta:** $300M ARR, 16,000 customers [33]. Primarily SOC 2 and broader GRC compliance automation. Vanta's platform is described as continuous monitoring and verification [33] but does not describe cryptographic or tamper-evident audit trail features. Vanta has expanded into AI governance (noting that "LLMs are 52% more likely to receive a high risk designation in Vanta than traditional SaaS" [33]), but this appears to be risk inventory management, not evaluation evidence attestation.

**Drata:** $100M+ ARR, cites EU AI Act and ISO 42001 as demand drivers [34]. Same pattern — compliance automation with AI-specific features, but no cryptographic evidence layer.

**HiddenLayer, Protect AI (now Prisma AIRS), CalypsoAI:** Security-focused products. HiddenLayer describes itself as "a security product, not a governance platform" [20]. No published cryptographic attestation capability.

**Holistic AI, Fairly AI, Trustible:** AI governance platforms with frameworks coverage (NIST AI RMF, EU AI Act, ISO 42001). No public evidence of cryptographic verification capabilities.

### 3.4 Closest Existing Players in the Specific White Space

**DeepInspect:** Described in one source as signing per-decision audit records "at commit, chained to the previous record, and committed to durable storage before the model response returns" [16]. This is the architecture closest to what this startup would build. However, the source quality is low and DeepInspect appears to be a small or early-stage company without publicly available pricing or significant market presence.

**WishKnish / Knish Proof:** A post-quantum (WOTS+) signed memory layer exposed via Model Context Protocol, described as pre-release [17]. No pricing disclosed. Exists in the cryptographic AI record space but has not achieved meaningful market presence.

**Aqta:** Publishes research on "signed AI decision records, runtime enforcement" [47]. Its Seal product signs attestation receipts using Ed25519 and canonical JSON [47]. Has a public log for checkpoint verification [47]. Appears to be very early stage — no customer or revenue data.

**Attested Intelligence:** Holds a patent on "Attested Governance Artifacts" (USPTO application 19/433,835, filed December 28, 2025) [43]. Ships an MCP governance proxy emitting Ed25519-signed, hash-linked receipts as offline-verifiable evidence bundles [43]. However, receipts are point-to-point, not published to a transparency log, and not encrypted to an owner key [43] — a meaningful architecture gap relative to a full witness log.

**Pipelock:** Has an operator-deployed mediator signing mode, but independent third-party witness signing is listed only as roadmap and has not shipped [43].

**Attestable:** Listed in one AI governance funding tracker as verifying "the integrity of AI computations," raising a $20M seed round led by TLV Partners and Altimeter Capital in August 2026 [41]. Middle East-based. This is the most direct known competitor in the cryptographic integrity space, though evidence is limited to a single secondary source.

**The Sello paper (arxiv, June 2026) [43]:** Proposes a formal protocol where the service receiving an agent's call signs a receipt, encrypts it to the owner, and publishes it to a witness-cosigned transparency log. The paper explicitly states "No system we surveyed delivers all five" required properties [43]. This academic paper validates the white space claim and provides the technical architecture direction.

### 3.5 White Space Summary

The white space is specific: **cryptographically signed, externally verifiable receipts that prove an AI safety evaluation (red-teaming, prompt injection testing, bias audit) was run as described, with independent witness infrastructure allowing any third party to verify the receipt without trusting the evaluating party.** No major vendor — not Vanta, not Credo AI, not HiddenLayer, not Braintrust — currently offers this as a core product. Credo AI's tamper-evident logging is the closest feature-level analog, but it operates within their platform rather than as open, independently verifiable infrastructure. The startup needs to establish the witness/notary layer as a neutral, third-party-trusted component; if it is operated exclusively by the vendor, the trust model is weakened.

---

## 4. ANALOGOUS MARKETS AND BUSINESS MODELS

This is the most instructive section for revenue model design. The pattern across all successful "trust infrastructure" markets is the same: **open the verifier and the standard; monetize the managed service, the enterprise SLA tier, and the compliance artifact generation.**

### 4.1 Software Supply Chain Attestation: Sigstore and Chainguard

**Sigstore** provides free, open-source signing and transparency tools (Rekor transparency log, Cosign signing tool, Fulcio certificate authority) [5]. The tools are free; the ecosystem lock-in is the transparency log and the standard. Sigstore is the verifier layer.

**Chainguard** builds commercial products on top of the Sigstore ecosystem: hardened container images with signed SBOMs and SLSA-level-2 provenance attestations [5]. Chainguard reached an estimated $100M ARR in June 2026 [5], valued at $3.5B [5]. Its pricing is structured around engineering-org size, not per-image: annual or monthly SaaS subscriptions from basic hardened images to FIPS-validated federal variants [5]. Each image comes with a signed SBOM and provenance attestation, providing compliance documentation for audits [5].

**The model:** Sigstore (open) = trust infrastructure / verifier. Chainguard (commercial) = managed, SLA-backed, compliance-ready artifacts built on that infrastructure. Customers pay not for the cryptography (which is open) but for the operational reliability, pre-built integrations, audit-ready report generation, and expert support.

**Direct applicability:** An "AI safety evaluation infrastructure" company should follow this model exactly. Sigstore's Rekor transparency log is the reference implementation for the witness layer — the arxiv Sello paper already uses Sigstore Rekor as its v0.1 reference log [43]. The startup should consider contributing an AI evaluation attestation profile to the SCITT (Supply Chain Integrity, Transparency, and Trust) working group at the IETF [43], which is standardizing COSE_Sign1 transparency receipts. Open-source the verifier; run the managed witness log commercially.

### 4.2 Certificate Authorities and Certificate Transparency

**Certificate Transparency (CT) logs** are public, append-only logs of TLS certificates, operated by multiple parties (Google, Cloudflare, Let's Encrypt) for redundancy and trust. The *verifier* (checking a certificate against CT logs) is free. Certificate authorities like DigiCert charge for the certificate issuance and management services built on top.

**DigiCert's model:** Per-certificate fees ($15–$300+ per year for DV/OV/EV certificates, enterprise pricing for large volumes) plus managed PKI platform subscriptions. Trust comes from the CA's status in root stores; the revenue comes from the managed service.

**RFC 3161 Timestamping Authorities (TSAs):** Free or low-cost public TSAs exist (DigiCert, Sectigo offer TSA services); enterprise-grade TSAs with SLAs, long-term archive guarantees, and audit-ready documentation charge platform fees. The technical operation (computing a hash, signing it with a timestamp) is trivial; the value is the trusted third-party status and the long-term operational commitment.

**Direct applicability:** A startup operating an AI evaluation witness log should position itself as the RFC 3161 TSA equivalent for AI safety testing receipts. The witness role — accepting signed evaluation receipts, publishing them to a public log, and providing inclusion proofs — requires trusted third-party status and operational reliability. This is exactly what DigiCert charges for in the PKI world.

### 4.3 SOC 2 Compliance Automation: Vanta, Drata, Secureframe

This is the closest business model analog in terms of go-to-market, buyer persona, and pricing structure.

**Market size:** Compliance automation estimated at $1.3B, growing 18–22% annually [42]. Vanta at $300M ARR (16,000 customers) [33][42]; Drata at $100M+ ARR (7,000+ customers) [34][42]; Secureframe estimated ~$40M ARR [51].

**Pricing (estimates, not confirmed by vendors, gates behind sales calls [6]):**
- Small team (10–30 employees, single framework): Vanta $10K–$15K/year; Drata $7.5K–$12K/year; Secureframe $8K–$13K/year [6]
- Mid-size (30–100 employees, two frameworks): Vanta $18K–$30K/year; Drata $14K–$24K/year [6]
- Growth-stage (100–300 employees, three+ frameworks): Vanta $30K–$50K+/year; Drata $22K–$40K/year [6]

**Unit economics drivers:** Each additional compliance framework adds $5K–$15K in ACV [42]. Companies start at $7.5K/year for SOC 2 alone and grow to $30K–$50K across four to five frameworks [42]. Net revenue retention reportedly exceeds 120% due to framework upsell [42].

**Growth trajectory:** Vanta grew $10M → $100M ARR in two years; $100M → $200M in 15 months; $200M → $300M in nine months [33]. This growth rate was driven by the "SOC 2 as go-to-market gateway" phenomenon (over 70% of enterprise buyers require a SOC 2 before signing a software contract [42]).

**The parallel:** EU AI Act compliance — specifically the requirement to produce dated, signed, defensible evidence of AI safety testing — is becoming the equivalent of SOC 2 for AI products. The "AI Act compliance as go-to-market gateway" phenomenon is not yet as widespread as SOC 2, but the trajectory is clear. GPAI providers already need to demonstrate compliance to sell in the EU; high-risk system providers face the same in 2027.

**What Vanta/Drata don't do:** These platforms focus on evidence collection (pulling data from cloud infrastructure, CI/CD pipelines, etc.) and mapping it to control frameworks. They do not produce cryptographically signed, externally verifiable receipts that a third party can check without trusting the platform. This is the gap.

### 4.4 Clinical Trial Audit Trails: 21 CFR Part 11, Medidata, Veeva

**21 CFR Part 11** requires electronic records used in clinical trials to be trustworthy, reliable, and equivalent to paper records; this means audit trails, access controls, and protection against record alteration. Medidata and Veeva Vault dominate this market.

**Medidata Rave (clinical data management):** Enterprise platform pricing typically $500K–$5M+ per study or annually, depending on indication, complexity, and data volume. The audit trail is not sold separately — it is embedded in the regulated platform.

**Veeva Vault:** Similar enterprise pricing. Audit trails are a compliance feature within the platform, not a standalone product.

**The key lesson:** In clinical trials, the audit trail infrastructure is not a commodity add-on — it is the foundation of the platform's regulatory value proposition and a primary reason customers pay premium enterprise prices. Switching away from a compliant platform risks evidence gaps that could invalidate trial data. This creates extreme stickiness.

**The parallel:** AI safety evaluation infrastructure with cryptographic audit trails should be positioned similarly — not as an add-on feature, but as the foundational layer without which evaluation results are not legally defensible. The switching cost of re-doing evaluations without verifiable records (or the audit liability of gaps in the chain) creates lock-in analogous to clinical data management.

### 4.5 Pricing Model Synthesis

The pattern across all analogous markets suggests:

| Pricing Dimension | Analogous Market | Recommended Application |
|---|---|---|
| **Platform fee** (base access) | Vanta, Drata, Medidata | Base subscription for the witness infrastructure + dashboard |
| **Per-attestation / per-evaluation** | RFC 3161 TSAs, CT log submissions | Usage tier for high-volume evaluation runs |
| **Framework upsell** | Vanta (SOC 2 → ISO 27001 → GDPR) | EU AI Act → NIST AI RMF → ISO 42001 → sector-specific |
| **SLA tier** | Chainguard (basic → FIPS-validated) | Standard → Regulated → Sovereign (air-gapped witness) |
| **Certification/marketplace fees** | PKI trust stores | "Listed witness" status for audit firms using the platform |
| **Open source verifier** | Sigstore, PromptFoo | Trust moat; auditors and regulators verify independently |

---

## 5. CONCRETE REVENUE MODEL

### 5.1 Product Architecture and Tiering

The product has three functional layers, each with distinct monetization logic:

**Layer 1 (Free / Open Source): The Verifier**
An open-source CLI and library allowing anyone to verify that a given evaluation receipt (a) was cryptographically signed by the claimed evaluator, (b) is included in a specific witness log checkpoint, (c) has not been tampered with since signing. Published on GitHub under Apache 2.0 or MIT. This is Sigstore Cosign equivalent for AI evaluation receipts.

**Why open-source the verifier strengthens the business:** Trust infrastructure only works if independent parties can verify it without trusting the vendor. Regulators, auditors, insurers, and downstream deployers need to be able to run the verifier themselves. If only the vendor can verify, the receipts are not independently trustworthy — which defeats the entire value proposition. Open-sourcing the verifier converts it from a moat to a lock-in mechanism: once regulators and auditors adopt the verification standard, switching to an incompatible system requires re-issuing all prior attestations. The verifier also drives developer adoption and ecosystem growth (the "left-shift" strategy: developers integrate signing into their eval pipelines, creating a continuous stream of events entering the managed witness log). Chainguard follows exactly this logic: Sigstore is free and open, Chainguard's commercial product is what enterprises pay for [5].

**Layer 2 (Core Paid): Managed Witness Infrastructure**
A hosted, operated transparency log accepting signed evaluation receipts from customers and third-party evaluators, providing:
- Inclusion proofs (Merkle tree-based, following RFC 9162 / SCITT pattern [43])
- Public checkpoint publication (allowing independent verification)
- Long-term retention with SLA (10 years to match EU AI Act Annex IV requirements [32][48])
- API for submitting and querying receipts
- Dashboard for managing evaluation evidence inventory

**Layer 3 (Enterprise / Regulated): Compliance Artifact Generation**
- Pre-formatted evidence packages for EU AI Act Annex IV technical documentation [32], NIST AI RMF, ISO/IEC 42001, and sector-specific frameworks (NAIC Bulletin, OCC MRM guidance)
- Integration connectors for existing eval tools (PromptFoo, Inspect, Braintrust, LangSmith) — sign and anchor their output
- Audit-firm access tier: allow external auditors to submit verified queries against a customer's evaluation log
- Air-gapped / sovereign deployment for defense and healthcare customers with data residency requirements

### 5.2 Pricing Tiers and ACV Estimates

*Note: These are model recommendations based on analogous market data, not confirmed market prices. Actual willingness-to-pay requires customer discovery validation.*

**Free / Developer Tier:**
- Open-source verifier: $0
- Self-hosted witness node with community support: $0 (like running your own CT log)
- Rationale: Creates pipeline integration habits, generates network effects, drives enterprise pipeline

**Starter Tier — $24K/year ACV (~$2K/month):**
- Managed witness log
- Up to 500 evaluation receipts/month anchored
- Dashboard and basic API access
- SOC 2 Type II coverage for the witness infrastructure itself
- Target: AI startups, mid-market SaaS companies deploying LLMs, compliance teams building their first EU AI Act evidence files
- Comparable: Vanta small-team pricing ($10K–$15K) + premium for cryptographic guarantees [6]

**Professional Tier — $60K/year ACV (~$5K/month):**
- Up to 5,000 evaluation receipts/month
- Multi-framework compliance artifact generation (EU AI Act, NIST AI RMF, ISO 42001)
- Audit-firm access portal (allow external auditors to verify receipts)
- Integration connectors for top 5 eval tools
- 90-day retention guarantee with SLA
- Target: Enterprise LLM deployers in BFSI, healthcare, insurance with active regulatory deadlines; small AI labs
- Comparable: Drata mid-size pricing ($14K–$24K) + premium for cryptographic layer; Vanta growth-stage ($30K–$50K)

**Enterprise Tier — $120K–$250K/year ACV:**
- Unlimited receipts (or volume negotiated)
- 10-year retention guarantee (matching EU AI Act Annex IV [32] and GPAI Code of Practice [48])
- Air-gapped or sovereign deployment option
- Custom framework mapping (Fannie Mae, NAIC, sector-specific)
- Dedicated CSM and regulatory liaison support
- SLA: 99.99% availability for witness log; inclusion proof delivery < 500ms
- White-label option for audit firms building their own evidence services
- Target: Frontier AI labs (OpenAI, Anthropic, Mistral, etc.); Tier 1 banks; KPMG/BSI/Bureau Veritas building AI assurance service lines on top
- Comparable: Clinical trial data management platforms ($500K–$5M, though this is early-stage — discount to $120K–$250K initially)

**Audit Firm / Accredited Evaluator Channel:**
- Flat annual listing fee ($15K–$30K/year) to be a "registered evaluator" in the witness log ecosystem
- Revenue share or per-verification fee ($50–$200 per verified evaluation receipt package) for evaluators submitting receipts on behalf of their clients
- Comparable: Vanta's audit partner network (30+ CPA firms [6]); PKI root store listing

**Insurance / Underwriting Data Feed (Year 2–3):**
- Annual data feed subscription to AI risk insurers providing aggregate analytics on evaluation rigor across a customer portfolio
- Pricing TBD — likely $100K–$500K/year for Tier 1 reinsurers like Munich Re
- Value proposition: Provides the underwriting data that insurers currently lack [35] to price AI risk

### 5.3 ACV Estimates by Segment

| Segment | ACV Range | Rationale |
|---|---|---|
| AI labs / frontier model providers | $120K–$250K | High regulatory obligation (Art. 55 [31]), high stakes, 10-year records needed [48] |
| Tier 1 BFSI enterprises | $60K–$150K | OCC, NAIC, DORA obligations; existing compliance procurement muscle |
| Mid-market BFSI/insurance | $24K–$60K | NAIC Bulletin examination pressure; need basic evidence records |
| Healthcare enterprises | $60K–$120K | HIPAA audit controls [16]; high-risk AI Act deadline approaching; risk-averse procurement |
| AI audit firms (as infrastructure) | $30K–$80K (listing + per-verification) | Building service lines on top; B2B2C model |
| Government / defense | $120K–$300K | Sovereign deployment premium; long procurement cycles |
| AI red-teaming vendors (integration partners) | Revenue share | Sign and anchor their outputs; distribution channel |

### 5.4 Path from $0 to First $1M ARR

*This is a model projection, not a forecast. Actual outcomes depend heavily on execution, sales cycles, and regulatory timing.*

**Month 1–3: Foundation**
- Release open-source verifier (GitHub) and publish AI evaluation receipt format specification
- Launch self-hosted witness node documentation
- Apply for SCITT working group participation at IETF to position the format for standardization
- Target: 50–100 GitHub stars, 10–20 developers integrating the signing library into existing eval pipelines

**Month 3–6: First Revenue**
- Launch managed witness infrastructure in beta (hosted)
- Target 5–10 Starter tier customers ($24K/year) = $120K–$240K ARR
- Priority: 1–2 AI labs (even small ones) as reference customers; they provide the credibility signal for BFSI
- Likely acquisition path: developer-led (someone integrating PromptFoo or Inspect discovers the library → upgrades to managed witness log)

**Month 6–12: Enterprise Push**
- Hire one dedicated enterprise sales person with BFSI or healthcare compliance background
- Target 2–3 Professional tier customers ($60K/year) = additional $120K–$180K ARR
- Build first EU AI Act Annex IV evidence package template, validated with a friendly law firm or notified body
- Target: $400K–$600K ARR at month 12

**Month 12–18: First $1M ARR**
- Close 1 Enterprise tier customer ($120K–$150K ACV) — either a frontier AI lab or a Tier 1 bank
- Maintain Starter and Professional tier growth (5–8 new customers total)
- Launch audit firm channel (2–3 AI assurance firms as registered evaluators; $15K–$30K each)
- Total: $700K–$1.1M ARR at month 15–18

**Key milestones that unlock the path:**
1. **One reference AI lab customer.** GPAI providers face the most immediate regulatory pressure and have budget; a single well-known lab (even a European one like Mistral) validates the market.
2. **EU AI Office recognition or citation.** If the witness log format is cited in AI Office guidance, the addressable market multiplies overnight. This requires early engagement with the AI Office's standardization processes.
3. **Audit firm adoption.** When KPMG, BSI, or Bureau Veritas [8] adopt the format for their AI assurance service lines, every client they serve becomes a potential lead. BSI awarded its 50th ISO/IEC 42001 certificate in October 2026 [8] — the assurance market is real and growing.

### 5.5 Unit Economics

*Estimates based on analogous market benchmarks; actual unit economics require validation.*

| Metric | Starter | Professional | Enterprise |
|---|---|---|---|
| ACV | $24K | $60K | $150K |
| Gross margin (est.) | ~70% | ~75% | ~80% |
| CAC (est., self-serve / PLG) | $3K–$6K | $8K–$15K | $25K–$50K (field sales) |
| Payback period (est.) | 2–4 months | 2–4 months | 4–8 months |
| NRR (target, framework upsell) | 110–115% | 115–120% | 120–130% |

Gross margins are high because the core product (operating a transparency log and signing infrastructure) is computationally inexpensive. The main cost drivers are: (a) operational reliability of the witness log (99.99% SLA requires redundancy), (b) long-term storage for 10-year retention commitments, (c) compliance overhead (SOC 2 Type II for the platform itself), and (d) customer success and regulatory liaison for enterprise customers.

---

## 6. TAM / SAM / SOM ESTIMATES

### 6.1 Top-Down Market Sizing

**Important caveat:** No analyst firm publishes estimates specifically for "verifiable AI evaluation infrastructure" or "cryptographic AI audit attestation." The following estimates are constructed by triangulating across adjacent market estimates, with explicit reasoning for each step. All estimates should be treated as directional, not precise.

**AI Governance Software Market (TAM component 1):**
- Gartner estimates AI governance spending at $492M in 2026, surpassing $1B by 2030 [1]
- Grand View Research estimates the AI governance market at $308M in 2025, growing to $3.59B by 2033 at 36% CAGR [7]
- Multiple analyst estimates (Gartner, Mordor, Fortune Business Insights, etc.) cluster in a range of $275M–$783M for 2025/2026, with a defensible center of ~$400M [15]
- Forecast disagreement is wide (25%–40%+ CAGR depending on definition [15]); Gartner's 68% one-year growth estimate is likely optimistic [15]
- **Best estimate for 2026 AI governance software: $400M–$500M, growing to $1.0B–$1.5B by 2030** (using Gartner's $492M midpoint for 2026 [1] and conservative extrapolation)

**AI Red-Teaming Services Market (TAM component 2):**
- Research and Markets: $1.75B in 2025, growing to $2.26B in 2026 at 28.8% CAGR, projected $6.17B in 2030 [14]
- SNS Insider: $1.52B in 2025, growing to $20.22B by 2035 at 29.5% CAGR [13]
- Security and Red Teaming services within third-party AI assurance: $172M in 2026, growing at 39.4% CAGR [8]
- Note: These figures likely double-count professional services revenue from Big Four and consulting firms
- **Best estimate for AI red-teaming services: $1.5B–$2.3B in 2026** (the spread reflects definitional differences)

**Third-Party AI Assurance Services Market (TAM component 3):**
- Polaris Market Research: $680M in 2025, growing to $11.82B by 2034 at 37.2% CAGR [8]
- North America: 39.3% of 2026 revenue; BFSI: 29.5% of 2026 end-user revenue [8]
- Governance and Risk Assurance: 28.5% of service type revenue; Specialist AI Assurance Firms growing at 40.9% CAGR [8]

**GRC / Compliance Automation (Addressable adjacent market):**
- Compliance automation sub-segment: $2.8B in 2025, growing at 25%+ [51]
- Broader GRC platform market: $18.3B in 2025, projected $32.9B by 2032 [42]
- AI governance within GRC: growing at 30%+ [51]

### 6.2 TAM / SAM / SOM

**Total Addressable Market (TAM):**

The TAM for a company providing cryptographic AI evaluation evidence infrastructure is the intersection of: (a) organizations that conduct or commission AI safety evaluations, (b) organizations that face regulatory or contractual obligations to demonstrate those evaluations happened, and (c) organizations willing to pay for infrastructure rather than build in-house.

Combining AI governance software ($400M–$500M), AI assurance services ($680M), and the directly relevant portion of compliance automation, the gross TAM for AI trust infrastructure in 2026 is approximately **$2B–$3B**, with a reasonable projection to **$10B–$15B by 2030** (using 30–40% CAGR across segments, weighted toward the lower end given the definitional uncertainty).

*This TAM estimate is explicitly extrapolated and uncertain. The wide range (2–3x) reflects genuine uncertainty about how quickly regulatory obligations translate to procurement, and whether the market develops as standalone infrastructure or gets bundled into larger platforms.*

**Serviceable Addressable Market (SAM):**

The SAM is organizations that (a) conduct AI safety evaluations with enough frequency and regulatory obligation that point-in-time manual documentation is insufficient, and (b) operate in sectors with active regulatory pressure. This filters to:
- Frontier AI labs and GPAI model providers: ~50–100 globally with real EU AI Act obligations; $50M–$100M SAM at $120K–$250K ACV
- Tier 1 BFSI enterprises (globally): ~500–1,000 institutions with active model risk management obligations; $60M–$150M SAM
- Healthcare enterprises: ~200–500 organizations with HIPAA + approaching AI Act obligations; $20M–$60M SAM
- AI audit firms building service lines: ~50–100 firms globally; $5M–$15M SAM

**2026 SAM estimate: $150M–$300M** (explicitly uncertain; the low end assumes slow sales cycles and high bundling by incumbents)

**Serviceable Obtainable Market (SOM) — Year 1–3:**

A new entrant with a differentiated cryptographic evidence layer, 10–15 enterprise customers at $60K–$150K ACV, and 20–50 smaller customers at $24K, could achieve:
- Year 1: $500K–$1M ARR (10–15 customers across tiers)
- Year 2: $2M–$5M ARR (30–50 customers; first audit firm channel customers)
- Year 3: $5M–$15M ARR (100+ customers; insurance channel and GPAI lab dominance)

**SOM estimate: $5M–$15M ARR by Year 3**, representing 2–5% of the SAM. This is consistent with Vanta's trajectory ($10M → $100M ARR in two years) discounted for the earlier-stage market and greater technical specificity.

### 6.3 Confidence Calibration

| Market Estimate | Confidence | Key Uncertainty |
|---|---|---|
| AI governance software 2026: ~$400M–$500M | Medium | Definitional overlap with broader GRC; no single accepted definition [15] |
| AI assurance services 2025: ~$680M | Medium | Analyst methodology opaque; likely includes Big Four service revenues [8] |
| AI red-teaming 2025: ~$1.5B–$2.3B | Low-medium | Wide analyst disagreement; definitional issues [13][14] |
| TAM 2026: ~$2B–$3B | Low | Constructed estimate; depends heavily on regulatory timing |
| SAM 2026: ~$150M–$300M | Low | Requires customer discovery to validate willingness to pay specifically for evidence infrastructure |
| SOM Year 3: $5M–$15M ARR | Low (projection) | Highly dependent on execution, regulatory developments, incumbent response |

---

## 7. STRATEGIC RECOMMENDATIONS AND WATCHLIST

### Key Decisions for the Founding Team

**1. Standard-first strategy.** The witness log must be positioned as neutral infrastructure, not a vendor-controlled silo. Engage with the IETF SCITT working group now [43]; propose an AI evaluation receipt profile to the EU AI Office's standardization process (which is actively seeking input [30]); contribute the receipt format to an open standard. This is how Sigstore established itself as the default software supply chain signing infrastructure rather than a proprietary product.

**2. Audit firm channel is the fastest path to enterprise.** BSI, KPMG, Bureau Veritas, and Big Four firms are actively building AI assurance service lines [8]. They need infrastructure to issue defensible, verifiable evaluation certificates. Partnering with one audit firm as a launch channel — offering them a white-label or co-branded evaluator access tier — immediately gives you distribution into their enterprise clients.

**3. Solve the GPAI provider problem first.** The EU AI Act Article 55 obligation to "document adversarial testing" [31], combined with the Code of Practice requirement for documentation "protected from unintended alterations" [49], is the clearest, most specific regulatory mandate with real enforcement starting August 2026 (AI Office requests for information already sent [44]). This is the beachhead. Frontier AI labs and European GPAI providers have both the regulatory urgency and the technical sophistication to integrate a signing SDK quickly.

**4. Pricing model: platform fee + per-evaluation volume, not per-seat.** Unlike SOC 2 automation (which tracks employees and systems), AI evaluation infrastructure should be priced on evaluation activity volume. Enterprises run hundreds or thousands of evaluation jobs per month; pricing per job or per anchored receipt (with volume tiers) aligns cost to usage and allows small customers to start cheaply. The managed witness infrastructure fee should be a flat annual subscription with volume tiers.

**5. Sovereign/air-gapped tier is the defense and healthcare unlock.** The fastest-growing on-premises red-teaming segment is growing at 32.9% CAGR, "driven by data-privacy and compliance concerns in regulated industries" [13]. Classified AI evaluation at defense contractors and highly regulated healthcare systems cannot use shared cloud infrastructure. A sovereign deployment option — a standalone witness node that syncs checkpoints to a public log but processes data on-premises — unlocks these segments at 2–3× premium pricing.

### Watchlist Items

- **EU AI Office publication of standardized evaluation methodologies** under Article 53's delegated acts [30]: if the AI Office specifies a format for "comparable and verifiable" evaluation documentation, this is either a mandate tailwind or a competitor (if they specify an in-house format).
- **SCITT Working Group AI profile development**: The Sello paper explicitly notes that "No current SCITT WG draft applies the framework to AI agent tool calls" [43]. Being the first to contribute this profile would be a significant standard-setting advantage.
- **Attestable ($20M seed, August 2026 [41])**: The most direct known competitor. Monitor their product releases and any EU AI Office engagement.
- **Credo AI cryptographic roadmap**: Credo AI currently offers "automated hashing and retention of evidence" [10] but not externally verifiable witness logs. If they build a full witness infrastructure, the white space closes significantly.
- **Insurance market crystallization**: When a major reinsurer (Munich Re, Swiss Re) or specialty insurer conditions AI liability premiums on verified evidence of evaluation rigor, demand will spike. Monitor Munich Re aiSure product evolution [36] and Lloyd's Market Association AI working groups.
- **US federal AI liability framework**: The current administration's posture is deregulatory [27], but Congress has multiple AI audit bills in progress [22]. A federal mandate for verified AI evaluation evidence (similar to the federal FRONTIER Act [22]) would be a step-change demand trigger.

---

*This report synthesizes evidence from 51 sources as of November 20, 2026. Market size estimates, pricing benchmarks, and regulatory interpretations should be independently validated before making capital allocation decisions. Regulatory timelines in particular have been subject to revision (e.g., the Digital Omnibus deferral of EU AI Act high-risk deadlines [8][11]) and should be monitored continuously.*