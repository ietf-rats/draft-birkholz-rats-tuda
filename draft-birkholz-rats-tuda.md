---
title: 'Time-Based Uni-Directional Attestation'
abbrev: TUDA
docname: draft-birkholz-rats-tuda-latest
stand_alone: true
ipr: trust200902
area: Security
wg: RATS Working Group
kw: Internet-Draft
cat: std
consensus: true
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  comments: yes

author:
- ins: A. Fuchs
  name: Andreas Fuchs
  org: Fraunhofer Institute for Secure Information Technology
  abbrev: Fraunhofer SIT
  email: andreas.fuchs@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer Institute for Secure Information Technology
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: I. McDonald
  name: Ira E McDonald
  org: High North Inc
  abbrev: High North Inc
  email: blueroofmusic@gmail.com
  street: PO Box 221
  code: '49839'
  city: Grand Marais
  country: US
- ins: C. Bormann
  name: Carsten Bormann
  org: Universität Bremen TZI
  street: Bibliothekstr. 1
  city: Bremen
  code: D-28359
  country: Germany
  phone: +49-421-218-63921
  email: cabo@tzi.org
normative:
  RFC3161: timestamp
# in STD62
#  RFC3411: snmp
  RFC5247: eap
  RFC6690: link
  RFC8949: cbor
  RFC7230: http1
  RFC7252: coap
  RFC8820: lawn
# not used:
#  RFC7519: jwt
  RFC7540: http2
  RFC8040: restconf
# subscription not used
#  RFC8639:
#  RFC8640:
#  RFC8641:
  RFC8610: cddl

informative:
  RFC1213:
  # RFC3410: STD62
# in STD62
  # RFC3418:
  RFC2790:
  RFC4949:
  RFC5209: nea
  RFC6933:
  STD62:
#    title: Internet Standard 62
#    author:
#    seriesinfo:
#      STD: 62
#      RFCs: 3411 to 3418
#    date: 2002-12
# text using this is commented out:
#  I-D.ietf-sacm-terminology: sacmterm
  I-D.ietf-core-comi: comi
  I-D.ietf-sacm-coswid: coswid
  I-D.ietf-rats-reference-interaction-models: models
  I-D.ietf-rats-architecture: rats
  I-D.fedorkow-rats-network-device-attestation: riv
  I-D.birkholz-rats-coswid-rim: coswid-rim
  I-D.birkholz-rats-uccs: uccs
  SCALE:
    title: Improving Scalability for Remote Attestation
    author:
      ins: A. Fuchs
      name: Andreas Fuchs
    date: 2008
    seriesinfo:
      Master Thesis (Diplomarbeit),: Technische Universitaet Darmstadt, Germany
  Safford:
    title: Using IMA for Integrity Measurement and Attestation
    author:
    - ins: D. Safford
      name: David Safford
    - ins: M. Zohar
      name: Mimi Zohar
    - ins: R. Sailer
      name: Reiner Sailer
    seriesinfo:
      Linux Plumbers Conference 2009
    date: 2009
  Steffens:
    title: The linux Integrity Measurement Architecture and TPM-based Network Endpoint Assessment
    author:
      ins: A. Steffen
      name: Andreas Steffen
    seriesinfo:
      Linux Security Summit
    date: 2012
  PRIRA:
    title: Principles of Remote Attestation
    author:
    - ins: G. Coker
      name: George Coker
    - ins: J. Guttman
      name: Joshua Guttman
    - ins: P. Loscocco
      name: Peter Loscocco
    - ins: A. Herzog
      name: Amy Herzog
    - ins: J. Millen
      name: Jonathan Millen
    - ins: B. O'Hanlon
      name: Brian O'Hanlon
    - ins: J. Ramsdell
      name: John Ramsdell
    - ins: A. Segall
      name: Ariel Segall
    - ins: J. Sheehy
      name: Justin Sheehy
    - ins: B. Sniffen
      name: Brian Sniffen
    seriesinfo:
      Springer: International Journal of Information Security, Vol. 10, pp. 63-81
      DOI: 10.1007/s10207-011-0124-7
    date: 2011-04-23
  SFKE2008:
    title: Improving the scalability of platform attestation
    author:
    - ins: F. Stumpf
      name: Frederic Stumpf
    - ins: A. Fuchs
      name: Andreas Fuchs
    - ins: S. Katzenbeisser
      name: Stefan Katzenbeisser
    - ins: C. Eckert
      name: Claudia Eckert
    seriesinfo:
      ACM: >
        Proceedings of the 3rd ACM workshop on Scalable trusted computing - STC '08
      page: 1-10
      DOI: 10.1145/1456455.1456457
    date: 2008
  CEL:
    title: >
      DRAFT Canonical Event Log Format Version: 1.0, Revision: .12
    author:
    - org: TCG TNC Working Group
    date: 2018
  TPM12:
    title: >
      Information technology -- Trusted Platform Module -- Part 1: Overview
    seriesinfo:
      ISO/IEC: 11889-1
    date: 2009
  TPM2:
    title: >
      Trusted Platform Module Library Specification, Family 2.0, Level 00, Revision 01.16 ed.
    author:
    - org: Trusted Computing Group
    date: 2014
# not used
#  TEE:
#    title: >
#      TEE System Architecture v1.1, GPD_SPE_009
#    author:
#    - org: Global Platform
#    date: 2017
  PTS:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IFM_PTS_v1_0_r28.pdf
    title: TCG Attestation PTS Protocol Binding to TNC IF-M
    author:
    - org: TCG TNC Working Group
    date: 2011
  TCGGLOSS:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_Glossary_Board-Approved_12.13.2012.pdf
    title: TCG Glossary
    author:
    - org: TCG
    date: 2012
  TCGRIM:
    target: https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1-r13_2feb20.pdf
    title: TCG Reference Integrity Manifest (RIM) Information Model
    author:
    - org: TCG
    date: 2019
  AIK-Enrollment:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IWG_CMC_Profile_Cert_Enrollment_v1_r7.pdf
    title: A CMC Profile for AIK Certificate Enrollment
    author:
    - org: TCG Infrastructure Working Group
    date: 2011
  AIK-Credential:
    target: https://www.trustedcomputinggroup.org/wp-content/uploads/IWG-Credential_Profiles_V1_R1_14.pdf
    title: TCG Credential Profile
    author:
    - org: TCG Infrastructure Working Group
    date: 2007
  REST:
    target: http://www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf
    title: Architectural Styles and the Design of Network-based Software Architectures
    author:
    - ins: R. Fielding
      name: Roy Fielding
      org: University of California, Irvine
    date: 2000
    seriesinfo:
      Ph.D.: Dissertation, University of California, Irvine
  IEEE802.1AR:
    title: 802.1AR-2009 - IEEE Standard for Local and metropolitan area networks - Secure Device Identity
    author:
      org: IEEE Computer Society
    date: 2009
    seriesinfo:
      IEEE: Std 802.1AR
# not used
#  IEEE802.11P:
#    title: >
#      802.11P-2010 -- IEEE Standard for Information technology
#      -- Local and metropolitan area networks
#      -- Specific requirements
#      -- Part 11: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications
#         Amendment 6: Wireless Access in Vehicular Environments
#    author:
#      org: IEEE Computer Society
#    date: 2010
#    seriesinfo:
#      IEEE: Std 802.11P
  IEEE1609:
    title: 1609.4-2016 - IEEE Standard for Wireless Access in Vehicular Environments (WAVE) -- Multi-Channel Operation
    author:
      org: IEEE Computer Society
    date: 2016
    seriesinfo:
      IEEE: Std 1609.4

--- abstract

This document defines the method and bindings used to convey Evidence via Time-based Uni-Directional Attestation (TUDA) in Remote ATtestation procedureS (RATS).
TUDA does not require a challenge-response handshake and thereby does not rely on the conveyance of a nonce to prove freshness of remote attestation Evidence.
TUDA enables the creation of Secure Audit Logs that can constitute believable Evidence about both current and past operational states of an Attester.
In TUDA, RATS entities require access to a Handle Distributor to which a trustable and synchronized time-source is available.
The Handle Distributor takes on the role of a Time Stamp Authority (TSA) to distribute Handles incorporating Time Stamp Tokens (TST) to the RATS entities.
RATS require an Attesting Environment that generates believable Evidence.
While a TPM is used as the corresponding root of trust in this specification, any other type of root of trust can be used with TUDA.

--- middle

{:markers: sourcecode-markers="true"}

# Introduction

Remote ATtestation procedureS (RATS) describe the attempt to determine and appraise system properties, such as integrity and trustworthiness, of a remote peer -- the Attester -- by the use of a Verifier in support of Relying Parties that intend to interact with the Attester. The Verifier carries the burden of appraisal of detailed Evidence about an Attester's trustworthiness. Evidence is generated by the Attester and consumed by the Verifier. To support security decisions, the Verifier generates digestable Attestation Results that can be easily consumed by Relying Parties. The RATS architecture specifies the corresponding concepts and terms {{-rats}}.

TUDA uses the architectural constituents of the RATS Architecture, such as the roles Attester and Verifier, and defines a method to convey Conceptual Messages between them. TUDA uses the Uni-Directional Remote Attestation interaction model described in {{-models}}. While the Conceptual Message focused on in this document is RATS Evidence, any type of Conceptual Message content that requires a believable indication about the message's content freshness can be conveyed with TUDA (e.g. Attestation Results).

The conveyance of Evidence in RATS must ensure that Evidence always remains integrity protected, tamper-evident, originates from a trustable entity (or group of entities), and is accompanied by a proof of its freshness.

In contrast to bi-directional interactions as described by Challenge/Response Remote Attestation in {{-models}}, TUDA enables uni-directional conveyance in the interactions between Attester and Verifier. TUDA allows a Verifier to receive Evidence from an Attester without solicitation. Conversely, it allows a Verifier to retrieve Evidence from an Attester without it being generated ad-hoc. Exemplary applications of TUDA are the creation of beacons in vehicular environments {{IEEE1609}} or authentication mechanisms based on EAP {{-eap}}.

The generation of Evidence in RATS requires an Attesting Environment. In this specification, the root of trust acting as an Attesting Environment is a Trusted Platform Module (TPM, see {{TPM12}} and {{TPM2}}). The Protected Capabilities {{TCGGLOSS}} provided by a TPM support various activities in RATS, e.g., Claims collection and Evidence generation.

A trusted coupling of Evidence generation with a global timescale is enabled via a Handle Distributor.
Handles generated by a Handle Distributor can include nonces, signed timestamps, or other structured or opaque content used as qualifying data in Evidence generation.
In TUDA, all RATS entities, such as the entities taking on the roles of Attester and Verifier, can receive signed timestamps from the Handle Distributor.
These trusted timestamps replace nonces in Evidence generation and Evidence appraisal {{-models}}.

## Forward Authenticity

Nonces enable an implicit time-keeping in which the freshness of Evidence is inferred by recentness.
Recentness is estimated via the time interval between sending a nonce as part of a challenge for Evidence and the reception of Evidence based on that nonce (as outlined in the interaction model depicted in section 8.1 in {{-models}}).
Conversely, the omission of nonces in TUDA allows for explicit time-keeping where freshness is not inferred from recentness.
Instead, a cryptographic binding of a trusted synchronization to a global timescale in the Evidence itself allows for Evidence that can prove past operational states of an Attester.
To capture and support this concept, this document introduces the term Forward Authenticity.

Forward Authenticity:

: A property of secure communication protocols, in which later compromise of the long-term keys of a data origin does not compromise past authentication of data from that origin.
Forward Authenticity is achieved by timely recording of authenticity Claims from Target Environments (via "audit logs" during "audit sessions") that are authorized for this purpose and trustworthy (via endorsed roots of trusts, for example), in a time-frame much shorter than that expected for the compromise of the long-term keys.

: Forward Authenticity enables new levels of assurance and can be included in basically every protocol, such as ssh, YANG Push, router advertisements, link layer neighbor discovery, or even ICMP echo requests.

## TUDA Objectives

Time-Based Uni-directional Attestation is designed to:

* increase the confidence in authentication and authorization procedures,
* address the requirements of constrained-node networks,
* support interaction models that do not maintain connection-state over time, such as REST architectures {{REST}},
* be able to leverage existing management interfaces, such as SNMP ({{RFC3411}}). RESTCONF {{-restconf}} or CoMI {{-comi}} --- and corresponding bindings,
* support broadcast and multicast schemes (e.g. {{IEEE1609}}),
* be able to cope with temporary loss of connectivity, and to
* provide trustworthy audit logs of past endpoint states.

## Terminology

This document uses the terms defined in the RATS Architecture {{-rats}} and by the RATS Reference Interaction Models {{-models}}.

{::boilerplate bcp14}

# Remote Attestation Principles

Based on the RATS Architecture, the processing of TPM generated Evidence can be separated in three activities.

Evidence Generation:

: The retrieval of signed digests from an RTR based on a sequence of collected Claims about software component integrity (measurements).

Evidence Conveyance:

: The transfer of Evidence from the Attester to the Verifier via the Internet.

Evidence Appraisal:

: The validation of Evidence signatures as well as the assessment of Claim values in Evidence by comparing them with Reference Values.

TUDA is specified in support of these RATS activities that align with the definitions presented in {{PRIRA}} and {{TCGGLOSS}}.

## Authenticity of Evidence

Remote attestation Evidence is composed of a set of Claims (assertions about the trustworthiness of an Attester's Target Environments) that is accompanied by a proof of its veracity -- typically a signature based on shielded, private, and potentially use-restricted key material used as an Authentication Secret as specified in section 6 of {{-models}} (or a secure channel as illustrated in {{-uccs}}).
As key material alone is typically not self-descriptive with respect to its intended use (its semantics), the Evidence created via TUDA MUST be accompanied by two kinds of certificates that are cryptographically associated with a trust anchor (TA) {{RFC4949}} via certification paths:

* an Attestation Key (AK) Certificate (AK-Cert) that represents the attestation provenance of the Attesting Environment (see section 4.2. in {{-rats}}) that generates Evidence, and
* an Endorsement Key (EK) Certificate (EK-Cert) that represents the Protection Capabilities of an Attesting Environment the AK is stored in.

If a Verifier decides to trust the TA of both an AK-Cert and an EK-Cert presented by an Attester -- and thereby the included Claims about the trustworthiness of an Attester's Target Environments -- the Evidence generated by the Attester can be considered trustable and believable.
Ultimately, all trustable and believable Evidence MUST be appraised by a Verifier in order to assess the trustworthiness of the corresponding Attester.
Assertions represented via Claims MUST NOT be considered believable by themselves.

In this document, Evidence is generated via TPMs that come with an AK-Cert and a EK-Cert as a basis for believable Evidence generation.

## Generating Evidence about Software Component Integrity

Evidence generated by a TPM for TUDA is based on measured hash values of all software components deployed in Target Environments (see section 4.2. in {{-rats}}) before they are executed ("measure then execute").
The underlying concept of "Attestation Logs" is elaborated on in Section 2.4.2. of {{-riv}}.
This concept is implemented, for example, in the Linux kernel where it is called the Linux Integrity Measurement Architecture (IMA) {{Safford}} and used to generates such a sequence of hash values.
A representation for conveyance of corresponding event logs is described in the Canonical Event Log {{CEL}} specification.
Open source solutions, for example, based on {{-nea}} use an IMA log to enable remote attestation {{Steffens}}.

An Attester MUST generate such an event/measurement log.

<!-- This section details the processed data items, the requirements for system components, and corresponding operations to enable the generation of Evidence for TUDA where TPMs take on the role of roots of trust for storage and roots of trust for reporting {{TCGGLOSS}}. -->

## Measurements and Digests Generated by an Attester

A hash value of a software component is created before it is executed by Attesters.
These hash values are typically represented as event log entries referred to as measurements, which often occur in large quantities.
Capabilities such as Linux IMA can be used to generate these measurements on an Attester.
Measurements are chained by Attesters using a rolling hash function.
A TPM acts as a root of trust for storage (RTS) by providing an Extend ({{TPM12}}, {{TPM2}}) operation to feed hash values in a rolling hash function.
Each measurement added to the sequence of all measurements results in a new current digest hash value.
A TPM acts as a root of trust for reporting (RTR) by providing Quote ({{TPM12}}, {{TPM2}}) operations to generate a digest of all currently extended hash values as Evidence.

TUDA requirements on TPM primitive operations and the information elements processed by them are illustrated using pseudocode in Appendix C and D.

## Attesting Environments and Roots of Trust

The primitive operations used to generate an initial set of measurements at the beginning of an Attester's boot sequence MUST be provided by a Root of Trust for Measurement (RTM) that is a system component of the Attester.
An RTM MUST be trusted via trust-relationships to TAs enabled by appropriate Endorsements (e.g.,EK-Certs).
If a Verifier cannot trust an RTM, measurements based on values generated by the RTM MUST be considered invalid.
At least one RTM MUST be accessible to the first Attesting Environment in Attester conducting Layered Attestation (see section 4.3. in {{-rats}}).
An RTM MAY aggregate and retain measurements until the first RTS becomes available in a Layered Attestation procedure -- instead of feeding measurements into an RTS, instantly.
The Protection Capabilities of an RTM to also act as a temporary RTS MUST be trusted via trust-relationships to TAs enabled by appropriate Endorsements.
System components supporting the use of a TPM typically include such an appropriate RTM.
In general, feeding measurements from an initial RTM into a TPM is automated and separated from Protected Capabilities that provide Claims collection from Target Environments that are regular execution environments.
A TPM providing the Protection Capabilities for an isolated and shielded location to feed measurements into (integrity and confidentiality) is an appropriate RTS for TUDA.

The primitive operations used to store and chain measurements via a rolling hash function MUST be provided by an appropriate root of trust for storage (RTS) that is a system component of the Attester.
An RTS MUST be trusted via trust-relationships to TAs enabled by appropriate Endorsements (e.g.,EK-Certs).
If a Verifier cannot trust an RTS, Evidence generated based on digest values acquired from the RTS MUST be considered invalid.
An RTS MUST be accessible to all Attesting Environments that are chained in a Layered Attestation procedure.
A TPM providing the primitive operation for Extend is an appropriate RTM for TUDA.

The primitive operations used to generate Evidence based on digests MUST be provided by roots of trust for reporting (RTR) that are system components of the Attester.
An RTR MUST be be trusted via trust-relationships to TAs enabled by appropriate Endorsements (e.g.,EK-Certs).
If a Verifier cannot trust an RTR, Evidence generated by the RTR MUST be considered invalid.
A TPM providing the primitive operations for Quote is an appropriate RTR for TUDA.
In a Composite Device (see Section 3.5. in {{-rats}} conducting a Layered Attestation procedure, Attesting Environments MAY not be TPMs.
At least one Attesting Environment MUST be a TPM.
At least one TPM MUST act as an RTR.
Attesting Environments that are not TPMs MUST NOT act as an RTR.

A concise definition of the terms RTM, RTS, and RTR can be found in the Trusted Computing Group (TCG) Glossary {{TCGGLOSS}}.
An RTS and an RTR are often tightly coupled.
In TUDA, a Trusted Platform Module (TPM, see {{TPM12}} and {{TPM2}}) takes on the roles of an RTS and an RTR.
The specification in this document requires the use of a TPM as a component of the Attester.
The protocol part of this specification can also be used with other RTS and RTR as long as essential functional requirements are satisfied (e.g., a trusted relative source of time, such as a tick-counter).
A sequence of Layered Attestation using at least an RTM, RTS, and RTR enables an authenticated boot sequence typically referred to as Secure Boot.

## Indeterministic Measurements

The sequence of measurements that is extended into the RTS provided by a TPM may not be deterministic due to race conditions that are side-effects of parallelization.
Parallelization occurs, for example, between different isolated execution environments or separate software components started in a execution environment.
In order to enable the appraisal of Evidence in cases where sequence of measurement varies, a corresponding event log that records all measurements in sequence, such as the IMA log, has to be conveyed next to the Evidence as depicted in section 8.2. in {{-models}}.

In contrast to Evidence, event logs do not necessarily have to be integrity protected or tamper-evident.
Event logs are conveyed to a Verifier in order to compute the reference values required for comparison with digest values (output of TPM Quote operations).
While digest values MUST constitute Evidence, measurements in event logs MAY be part of Evidence, but do not have to be MAY be conveyed separately.
If the values in event logs or their sequence are tampered with before or during conveyance from an Attester to a Verifier, the corresponding Evidence Appraisal fails.
While this dependency reflects the intended behavior of RATS, integrity protected or tamper-evident can be beneficial or convenient in some usage scenarios.
Additionally, event logs my allow insights into the composition of an Attester and typically come with confidentiality requirements.

In order to compute reference values to compare digest Claims in Evidence with, a Verifier MUST be able to replay the rolling hash function of the Extend operation provided by a TPM (see Section 2.4.2. in {{-riv}}).

A Verifier has to replay the event log using its own extend operation with an identical rolling hash function in order to generate reference values as outlined in section 2.4.1. of {{-riv}}.
During reply, the validity of each event log record MUST be appraised individually by the Verifier in order to infer if each started software component satisfies integrity requirements.
These appraisal procedures require Reference Integrity Measurements/Manifests (RIM) as are provided via {{-coswid-rim}} or {{TCGRIM}}.
Each RIM includes Reference Values that are nominal reference hash values for sets of software components.
The Reference Values can be compared with hash values about executed software components included in an event log.
A Verifier requires an appropriate set of RIMs to compare every record in an event log successfully.
RIMs or other sets Reverence Value are supplied by Reference Value Providers as defined in the RATS Architecture {{-rats}}.
Corresponding procedures that enable a Verifier to acquire Reference Values are out-of-scope of this document.

# TUDA Principles and Requirements

Traditional remote attestation protocols typically use bi-directional challenge/response interaction models. Examples include the Platform Trust Service protocol {{PTS}} or CAVES {{PRIRA}}, where one entity sends a challenge that is included inside the response to prove the freshness of Evidence via recentness. The corresponding interaction model depicted in Section 8.1. of {{-models}} tightly couples the three RATS activities of generating, conveying and appraising Evidence.

Time-Based Uni-directional Attestation can decouple these three activities. As a result, TUDA provides additional capabilities, such as:

* remote attestation for Attesters that might not always be able to reach the Internet by enabling the appraisal of past states,
* secure audit logs by combining the Evidence generated with integrity measurement logs (e.g. IMA logs) that represent a detailed record of corresponding past states,
* the use of the uni-directional interaction model {{-models}} that can traverse "diode-like" network security functions (NSF) or can be leveraged RESTful telemetry as enabled by the CoAP Observe option {{-coap}}).

## Attesting Environment Requirements

An Attesting Environment that generates Evidence in TUDA MUST support three specific Protected Capabilities:

* Platform Configuration Registers (PCR) that can extend measurements consecutively and represent the sequence of measurements as a single digest,
* Restricted Signing Keys (RSK) that can only be accessed, if a specific signature about a set of measurements can be provided as authentication, and
* a dedicated source of (relative) time, e.g. a tick counter (a tick being a specific time interval, for example 10 ms).

A TPM is capable of providing these Protected Capabilities for TUDA.

## Handle Distributor Requirements: Time Stamp Authority

Both Evidence generation and Evidence appraisal require a Handle Distributor that can take on the role of a trusted Time Stamp Authority (TSA) as an additional third party.
Time Stamp Tokens (TST) included in Handles MUST be generated by Time Stamp Authority based on {{RFC3161}} that acts as the Handle Distributor.
The combination of a local source of time provided by a TPM (on the Attester) and the TST provided by the Handle Distributor (to both the Attester and the Verifier) enable an appropriate proof of freshness.

# Information Elements and Conveyance

TUDA defines a set of information elements (IE) that represent a set of Claims, are generated and stored on the Attester, and are intended to be transferred to the Verifier in order to enable the appraisal of Evidence. Each TUDA IE:

* MUST be encoded in the Concise Binary Object Representation (CBOR {{-cbor}}) to minimize the volume of data in motion. In this document, the composition of the CBOR data items that represent IE is described using the Concise Data Definition Language, CDDL {{-cddl}}.
* that requires a certain freshness SHOULD only be re-generated when out-dated (not fresh, but stale), which reduces the overall resources required from the Attester, including the usage of a TPM's resources (re-generation of IE is determined by their age or by specific state changes on the Attester, e.g., due to a reboot-cycle)
* SHOULD only be transferred when required, which reduces the amount of data in motion necessary to conduct remote attestation significantly (only IE that have changed since their last conveyance have to be transferred)
* that requires a certain freshness SHOULD be reused for multiple remote attestation procedures in the limits of its corresponding freshness-window, further reducing the load imposed on the Attester and corresponding TPMs.

# TUDA Core Concept

Traditional Challenge/Response Remote Attestation {{-models}} includes sending a nonce in the challenge to be used in ad-hoc Evidence generation. Using the TPM 1.2 as an example, a corresponding nonce-challenge would be included within the signature created by the TPM_Quote command in order to prove the freshness of a response containing evidence, see e.g. {{PTS}}.

In contrast, the TUDA protocol uses the combined output of TPM_CertifyInfo and TPM_TickStampBlob. The former provides a proof about the Attester's state by creating Evidence that a certain key is bound to that state. The latter provides proof that the Attester was in the specified state by using the bound key in a time operation. This combination enables a time-based attestation scheme. The approach is based on the concepts introduced in {{SCALE}} and {{SFKE2008}}.

Each TUDA IE has an individual time-frame, in which it is considered to be fresh (and therefore valid and trustworthy). In consequence, each TUDA IE that composes data in motion is based on different methods of creation.

As highlighted above, the freshness properties of a challenge-response based protocol enable implicit time-keeping via a time window between:

* the time of transmission of the nonce, and
* the reception of the corresponding response.

Given the time-based attestation scheme, the freshness property of TUDA is equivalent to that of bi-directional challenge response attestation, if the point-in-time of attestation lies between:

* the transmission of a TUDA time-synchronization token, and
* the typical round-trip time between the Verifier and the Attester.

The accuracy of this time-frame is defined by two factors:

* the time-synchronization between the Attester and the Handle Distributor. The time between the two tickstamps acquired via the RoT define the scope of the maximum drift (time "left" and time "right" in respect to the timeline) to the handle including the signed timestamp, and
* the drift of clocks included in the RoT.

Since the conveyance of TUDA Evidence does not rely upon a Verifier provided value (i.e. the nonce), the security guarantees of the protocol only incorporate the Handle Distributor and the RoT used. In consequence, TUDA Evidence can even serve as proof of integrity in audit logs with precise point-in-time guarantees.

{{rest}} contains guidance on how to utilize a REST architecture.

{{snmp}} contains guidance on how to create an SNMP binding and a corresponding TUDA-MIB.

{{yang}} contains a corresponding YANG module that supports both RESTCONF and CoREDONF.

{{tpm12}} contains a realization of TUDA using TPM 1.2 primitives.

{{tpm2}} contains a realization of TUDA using TPM 2.0 primitives.

<!--
# Terminology

This document introduces roles, information elements and types required to conduct TUDA and uses terminology (e.g. specific certificate names) typically seen in the context of attestation or hardware security modules.


## Universal Terms

Attestation Identity Key (AIK):

: A special purpose signature (therefore asymmetric) key that supports identity related operations. The private portion of the key pair is maintained confidential to the entity via appropriate measures (that have an impact on the scope of confidence). The public portion of the key pair may be included in AIK credentials that provide a claim about the entity.

TUDA Evidence Generation:

: The creation of evidence on the Attester that provides proof of a set of the Attester's integrity measurements. This is done by digitally signing a set of PCRs using an AIK protected and operated on by a RoT.

Identity:

: A set of claims that is intended to be related to an entity.

Integrity Measurements:

: Metrics of endpoint characteristics (i.e. composition, configuration and state) that
affect the confidence in the trustworthiness of an endpoint. Digests of integrity measurements
can be stored in shielded locations (i.e. PCR of a TPM).

Reference Integrity Measurements:

: Signed measurements about the characteristics of an Attester's characteristics that are provided by an Endorser and are intended to be used as declarative guidance {{- sacmterm}} (e.g. a signed CoSWID as defined in {{-coswid-rim}}).

Trustworthy:

: A quality of an Attester that it does exactly what it is expected to do and nothing else.

## Roles

Attester:
: the endpoint that is the subject of the attestation to another endpoint.

Verifier:
: the endpoint that consumes the attestation of another endpoint to conduct a verification.

TSA:
: a Time Stamp Authority {{-timestamp}}

### General Types

Byte:
: the now customary synonym for octet

Cert:
: an X.509 certificate represented as a byte-string

-->

## TPM Specific Terms

PCR:

: A Platform Configuration Register that is part of the TPM and is used to securely store and report measurements about security posture

PCR-Hash:

: A hash value of the security posture measurements stored in a TPM PCR (e.g. regarding running software instances) represented as a byte-string

## Certificates

HD-CA:

: The Certificate Authority that provides the certificate for the TSA role of a Handle Distributor (HD)

AIK-CA:

: The Certificate Authority that provides the certificate for the AK of the TPM. This is the client platform credential for this protocol. It is a placeholder for a specific CA and AK-Cert is a placeholder for the corresponding certificate, depending on what protocol was used. The specific protocols are out of scope for this document, see also {{AIK-Enrollment}} and {{IEEE802.1AR}}.

# The TUDA Protocol Family

Time-Based Uni-Directional Attestation consists of the following seven information elements:

Handle Distributor Certificate:

: The certificate of the Handle Distributor that takes on the role of TSA. The Handle Distributor certificate is used in a subsequent synchronization protocol tokens. This certificate is signed by the HD-CA.

AK Certificate:

: A certificate about the Attestation Key (AIK) used. An AK-Cert may be an {{IEEE802.1AR}} IDevID or LDevID, depending on their setting of the corresponding identity property ({{AIK-Credential}}, {{AIK-Enrollment}}; see {{aik}}).

Synchronization Token:

: The reference frame for Evidence is provided by the relative timestamps generated by the TPM. In order to put Evidence into relation with a Real Time Clock (RTC), it is necessary to provide a cryptographic synchronization between these trusted relative timestamps and the regular RTC that is a hardware component of the Attester. To do so, trustable timestamps are acquired from a Handle Distributor.

Restriction Info:

: Evidence Generation relies on the capability of the Rot to operate on restricted keys. Whenever the PCR values of an Attesting Environment change, a new restricted key is created that can only be operated as long as the PCRs remain in their current state.

: In order to prove to the Verifier that this restricted temporary key actually has these properties and also to provide the PCR value that it is restricted, the corresponding signing capabilities of the RoT are used. The TPM creates a signed certificate using the AK about the newly created restricted key.

Measurement Log:

: A Verifier requires the means to derive the PCRs' values in order to appraise the trustworthiness of an Attester. As such, a list of those elements that were extended into the PCRs is reported. For certain environments, this step may be optional if a list of valid PCR configurations (in the form of RIM available to the Verifier) exists and no measurement log is required.

Implicit Evidence:

: The actual Evidence is then based on a signed timestamp provided by the RoT using the restricted temporary key that was certified in the steps above. The signed timestamp generated provides the trustable assertion that at this point in time (with respect to the relative time of the TPM
s tick counter) a certain configuration existed (namely the PCR values associated with the restricted key). In combination with the synchronization token this timestamp represented in relative time can then be related to the real-time clock.

Concise SWID tags:

: As an option to better assess the trustworthiness of an Attester, a Verifier can request the reference hashes (RIM, sometimes called golden measurements, known-good-values, or nominal values) of all started software components to compare them with the entries in a measurement log. References hashes regarding installed (and therefore running) software can be provided by the manufacturer via SWID tags. SWID tags are provided by the Attester using the Concise SWID representation {{-coswid}} and bundled into a collection (a RIM Manifest {{-coswid-rim}}).

These information elements can be sent en bloc, but it is recommended
to retrieve them separately to save bandwidth, since these
elements have different update cycles. In most cases, retransmitting
all seven information elements would result in unnecessary redundancy.

Furthermore, in some scenarios it might be feasible not to store all
elements on the Attester, but instead they could be retrieved
from another location or be pre-deployed to the Verifier.
It is also feasible to only store public keys on the Verifier and skip certificate provisioning completely in order to save bandwidth and computation time for certificate verification.

## TUDA Information Elements Update Cycles {#updatecycles}

An Attester can be in various states during its uptime cycles. For TUDA, a subset of these states (which imply associated information) are important to the Evidence Generation. The specific states defined are:

* persistent, even after a hard reboot: includes certificates
  that are associated with the endpoint itself or with services it relies on.

* volatile to a degree: may change at the beginning of each boot cycle.
  This includes the capability of a TPM to provide relative time which provides the basis for the synchronization token and implicit attestation -- and which can reset after an Attester is powered off.

* very volatile: can change during any time of an uptime cycle
  (periods of time an Attester is powered on, starting with its boot sequence).
  This includes the content of PCRs of a hardware RoT and thereby also the PCR-restricted signing keys used for attestation.

Depending on this "lifetime of state", data has to be transported over the wire, or not. E.g. information that does not change due to a reboot typically has to be transported only once between the Attester and the Verifier.

There are three kinds of events that require fresh Evidence to be generated:

* The Attester completes a boot-cycle
* A relevant PCR changes
* Too much time has passed since the Evidence Generation

The third event listed above is variable per application use case and also depends on the precision of the clock included in the RoT.
For usage scenarios, in which the Attester would periodically
push information to be used in an audit-log, a time-frame of approximately one update per minute should be sufficient. For those usage scenarios, where Verifiers request (pull) fresh Evidence, an implementation could potentially use a TPM continuously to always present the most freshly created Evidence. This kind of utilization can result in a bottle-neck with respect to other purposes: if unavoidable, a periodic interval of once per ten seconds is recommended, which typically leaves about 80% of available TPM resource for other applications.

<!--

AIK-Token only once for the lifetime

Sync-Token only once per boot-cycle. Or when clock-drift gets too big

CertifyInfo whenever PCRs change, since new key gets created

MeasurementLog whenever PCRs have changed in order to validate new PCRs

Implicit Attestation for each time that an attestation is needed

-->

The following diagram is based on the reference interaction model found in section 8.1. of {{-models}} and is enriched with the IE update cycles defined in this section.

~~~~
.----------.                                                .----------.
| Attester |                                                | Verifier |
'----------'                                                '----------'
     |                                                            |
   boot                                                           |
     |                                                            |
valueGeneration(targetEnvironment)                                |
     | => claims                                                  |
     |                   .--------------------.                   |
     | <----------handle |                    |                   |
     |                   | Handle Distributor |                   |
     |                   |                    | handle----------> |
     |                   '--------------------'                   |
syncTokenGeneration                                               |
     | => syncToken                                               |
     |                                                            |
restrictedKeyGeneration                                           |
restrictedKeyCertify                                              |
     |                                                            |
evidenceGeneration(handle, authSecIDs, collectedClaims)           |
     | => evidence                                                |
     |                                                            |
     | pushAKCert ----------------------------------------------> |
     | pushSyncToken -------------------------------------------> |
     | pushCertifyInfo -----------------------------------------> |
     | pushEventLog --------------------------------------------> |
     | pushEvidenceon ------------------------------------------> |
     |                                                            |
     |                  evidenceAppraisal(evidence, eventLog, refClaims)
     |                                       attestationResult <= |
     ~                                                            ~
  pcr-change                                                      |
     |                                                            |
restrictedKeyGeneration                                           |
restrictedKeyCertify                                              |
     |                                                            |
evidenceGeneration(handle, authSecIDs, collectedClaims)           |
     | => evidence                                                |
     |                                                            |
     | pushCertifyInfo -----------------------------------------> |
     | pushEventLog --------------------------------------------> |
     | pushEvidenceon ------------------------------------------> |
     |                                                            |
     |                  evidenceAppraisal(evidence, eventLog, refClaims)
     |                                       attestationResult <= |
     |                                                            |
~~~~
{: #SequenceExample title="Example sequence of events"}

#  Sync Base Protocol

The uni-directional approach of TUDA requires evidence on how the TPM time represented in ticks (relative time since boot of the TPM) relates to the standard time provided by the TSA.
The Sync Base Protocol (SBP) creates evidence that binds the TPM tick time to the TSA timestamp. The binding information is used by and conveyed via the Sync Token (TUDA IE). There are three actions required to create the content of a Sync Token:

* At a given point in time (called "left"), a signed tickstamp counter value is acquired from the hardware RoT. The hash of counter and signature is used as a nonce in the request directed at the TSA.
* The corresponding response includes a data-structure incorporating the trusted timestamp token and its signature created by the TSA.
* At the point-in-time the response arrives (called "right"), a signed tickstamp counter value is acquired from the hardware RoT again, using a hash of the signed TSA timestamp as a nonce.

The three time-related values --- the relative timestamps provided by the hardware RoT ("left" and "right") and the TSA timestamp --- and their corresponding signatures are aggregated in order to create a corresponding Sync Token to be used as a TUDA Information Element that can be conveyed as evidence to a Verifier.

The drift of a clock incorporated in the hardware RoT that drives the increments of the tick counter constitutes one of the triggers that can initiate a TUDA Information Element Update Cycle in respect to the freshness of the available Sync Token.

<!-- The following functions illustrate the worst case freshness-window assuming the maximum drift of TPM tick counters that is considered acceptable in respect to the standard time - 15 percent - as defined by the TPM specification: -->

#  IANA Considerations {#iana}

This memo includes requests to IANA, including registrations for media
type definitions.

TBD


#  Security Considerations

There are Security Considerations. TBD

# Contributors

TBD

--- back

# REST Realization {#rest}

Each of the seven data items is defined as a media type ({{iana}}).
Representations of resources for each of these media types can be
retrieved from URIs that are defined by the respective servers {{-lawn}}.
As can be derived from the URI, the actual retrieval is via one of the HTTPs
({{-http1}}, {{-http2}}) or CoAP {{-coap}}.  How a client obtains
these URIs is dependent on the application; e.g., CoRE Web links {{-link}}
can be used to obtain the relevant URIs from the self-description of a
server, or they could be prescribed by a RESTCONF data model {{-restconf}}.

# SNMP Realization {#snmp}

SNMPv3 [STD62] {{RFC3411}} is widely available on computers and also constrained devices.
To transport the TUDA information elements, an SNMP MIB is defined below which
encodes each of the seven TUDA information elements into a table.  Each row in a
table contains a single read-only columnar SNMP object of datatype OCTET-STRING.
The values of a set of rows in each table can be concatenated to reconstitute a
CBOR-encoded TUDA information element.  The Verifier can retrieve the values for
each CBOR fragment by using SNMP GetNext requests to "walk" each table and can
decode each of the CBOR-encoded data items based on the corresponding CDDL {{-cddl}}
definition.

Design Principles:

1. Over time, TUDA attestation values age and should no longer be used.  Every
   table in the TUDA MIB has a primary index with the value of a separate
   scalar cycle counter object that disambiguates the transition from one
   attestation cycle to the next.

2. Over time, the measurement log information (for example) may grow
   large. Therefore, read-only cycle counter scalar objects in all TUDA MIB object
   groups facilitate more efficient access with SNMP GetNext requests.

3. Notifications are supported by an SNMP trap definition with all of the cycle
   counters as bindings, to alert a Verifier that a new attestation cycle has
   occurred (e.g., synchronization data, measurement log, etc. have been updated
   by adding new rows and possibly deleting old rows).

## Structure of TUDA MIB

The following table summarizes the object groups, tables and their indexes, and conformance requirements for the TUDA MIB:

| Group/Table | Cycle | Instance | Fragment | Required |
|-------------|-------|----------|----------|----------|
| General     |       |          |          | x        |
| AIKCert     | x     | x        | x        |          |
| TSACert     | x     | x        | x        |          |
| SyncToken   | x     |          | x        | x        |
| Restrict    | x     |          |          | x        |
| Measure     | x     | x        |          |          |
| VerifyToken | x     |          |          | x        |
| SWIDTag     | x     | x        | x        |          |

### Cycle Index

A tudaV1\<Group\>CycleIndex is the:

1. first index of a row (element instance or element fragment) in the
tudaV1\<Group\>Table;
1. identifier of an update cycle on the table, when rows were added and/or
deleted from the table (bounded by tudaV1\<Group\>Cycles); and
1. binding in the tudaV1TrapV2Cycles notification for directed polling.


### Instance Index

A tudaV1\<Group\>InstanceIndex is the:

1. second index of a row (element instance or element fragment) in the
tudaV1\<Group\>Table; except for
1. a row in the tudaV1SyncTokenTable (that has only one instance per cycle).


### Fragment Index

A tudaV1\<Group\>FragmentIndex is the:

1. last index of a row (always an element fragment) in the
tudaV1\<Group\>Table; and
1. accomodation for SNMP transport mapping restrictions for large string
elements that require fragmentation.

## Relationship to Host Resources MIB

The General group in the TUDA MIB is analogous to the System group in the
Host Resources MIB [RFC2790] and provides context information for the TUDA
attestation process.

The Verify Token group in the TUDA MIB is analogous to the Device group in
the Host MIB and represents the verifiable state of a TPM device and its
associated system.

The SWID Tag group (containing a Concise SWID reference hash profile {{-coswid}}) in the TUDA MIB is analogous to the Software Installed and
Software Running groups in the Host Resources MIB [RFC2790].


## Relationship to Entity MIB

The General group in the TUDA MIB is analogous to the Entity General group in
the Entity MIB v4 [RFC6933] and provides context information for the TUDA
attestation process.

The SWID Tag group in the TUDA MIB is analogous to the Entity Logical group
in the Entity MIB v4 [RFC6933].


## Relationship to Other MIBs

The General group in the TUDA MIB is analogous to the System group in MIB-II
[RFC1213] and the System group in the SNMPv2 MIB [RFC3418] and provides
context information for the TUDA attestation process.

## Definition of TUDA MIB

~~~~ SMIv2
{::include ietf-tuda.mib}
~~~~
{: markers}

# YANG Realization {#yang}

~~~~ YANG
{::include TUDA-V1-ATTESTATION-MIB.yang}
~~~~
{: markers}

# Realization with TPM functions

## TPM Functions

The following TPM structures, resources and functions are used within this approach.
They are based upon the TPM specifications {{TPM12}} and {{TPM2}}.

### Tick-Session and Tick-Stamp

On every boot, the TPM initializes a new Tick-Session. Such a tick-session consists
of a nonce that is randomly created upon each boot to identify the current boot-cycle
-- the phase between boot-time of the device and shutdown or power-off --
and prevent replaying of old tick-session values. The TPM uses its internal entropy
source that guarantees virtually no collisions of the nonce values between two of such
boot cycles.

It further includes an internal timer that is being initialize to Zero on each
reboot. From this point on, the TPM increments this timer continuously based upon its
internal secure clocking information until the device is powered down or set to sleep.
By its hardware design, the TPM will detect attacks on any of those properties.

The TPM offers the function TPM_TickStampBlob, which allows the TPM to create a signature
over the current tick-session and two externally provided input values. These input values
are designed to serve as a nonce and as payload data to be included in a TickStampBlob:
TickstampBlob := sig(TPM-key, currentTicks || nonce || externalData).

As a result,
one is able to proof that at a certain point in time (relative to the tick-session)
after the provisioning of a certain nonce, some certain externalData was known and
provided to the TPM. If an approach however requires no input values or only one
input value (such as the use in this document) the input values can be set to well-known
value. The convention used within TCG specifications and within this document is to
use twenty bytes of zero h'0000000000000000000000000000000000000000' as well-known
value.


### Platform Configuration Registers (PCRs)

The TPM is a secure cryptoprocessor that provides the ability to store measurements
and metrics about an endpoint's configuration and state in a secure, tamper-proof
environment. Each of these security relevant metrics can be stored in a volatile
Platform Configuration Register (PCR) inside the TPM. These measurements can be
conducted at any point in time, ranging from an initial BIOS boot-up sequence to
measurements taken after hundreds of hours of uptime.

The initial measurement is triggered by the Platforms so-called pre-BIOS or ROM-code.
It will conduct a measurement of the first loadable pieces of code; i.e.\ the BIOS.
The BIOS will in turn measure its Option ROMs and the BootLoader, which measures the
OS-Kernel, which in turn measures its applications. This describes a so-called measurement
chain. This typically gets recorded in a so-called measurement log, such that the
values of the PCRs can be reconstructed from the individual measurements for validation.

Via its PCRs, a TPM provides a Root of Trust that can, for example, support secure
boot or remote attestation. The attestation of an endpoint's identity or security
posture is based on the content of an TPM's PCRs (platform integrity measurements).


### PCR restricted Keys

Every key inside the TPM can be restricted in such a way that it can only be used
if a certain set of PCRs are in a predetermined state. For key creation the desired
state for PCRs are defined via the PCRInfo field inside the keyInfo parameter.
Whenever an operation using this key is performed, the TPM first checks whether
the PCRs are in the correct state. Otherwise the operation is denied by the TPM.

### CertifyInfo

The TPM offers a command to certify the properties of a key by means of a signature
using another key. This includes especially the keyInfo which in turn includes the PCRInfo information
used during key creation. This way, a third party can be assured about the fact that
a key is only usable if the PCRs are in a certain state.

## IE Generation Procedures for TPM 1.2 {#tpm12}

### AIK and AIK Certificate {#aik}

Attestations are based upon a cryptographic signature performed by the TPM using
a so-called Attestation Identity Key (AIK). An AIK has the properties that it cannot
be exported from a TPM and is used for attestations. Trust in the AIK is established
by an X.509 Certificate emitted by a Certificate Authority. The AIK certificate is
either provided directly or via a so-called PrivacyCA {{AIK-Enrollment}}.

This element consists of the AIK certificate that includes the AIK's public key used
during verification as well as the certificate chain up to the Root CA for validation
of the AIK certificate itself.

~~~~ CDDL
TUDA-Cert = [AIK-Cert, TSA-Cert]; maybe split into two for SNMP
AIK-Cert = Cert
TSA-Cert = Cert
~~~~
{:cddl #cert-token title="TUDA-Cert element in CDDL"}

The TSA-Cert is a standard certificate of the TSA.

The AIK-Cert may be provisioned in a secure environment using standard means or
it may follow the PrivacyCA protocols. {{make-cert-token}} gives a rough sketch
of this protocol. See {{AIK-Enrollment}} for more information.

The X.509 Certificate is built from the AIK public key and the
corresponding PKCS #7 certificate chain, as shown in
{{make-cert-token}}.

Required TPM functions:

~~~~ pseudocode
| create_AIK_Cert(...) = {
|   AIK = TPM_MakeIdentity()
|   IdReq = CollateIdentityRequest(AIK,EK)
|   IdRes = Call(AIK-CA, IdReq)
|   AIK-Cert = TPM_ActivateIdentity(AIK, IdRes)
| }
|
| /* Alternative */
|
| create_AIK_Cert(...) = {
|   AIK = TPM_CreateWrapKey(Identity)
|   AIK-Cert = Call(AIK-CA, AIK.pubkey)
| }
~~~~
{: #make-cert-token title="Creating the TUDA-Cert element"}

### Synchronization Token

The reference for Attestations are the Tick-Sessions of the TPM. In order to put Attestations
into relation with a Real Time Clock (RTC), it is necessary to provide a cryptographic
synchronization between the tick session and the RTC. To do so, a synchronization
protocol is run with a Time Stamp Authority (TSA) that consists of three steps:

- The TPM creates a TickStampBlob using the AIK
- This TickStampBlob is used as nonce to the Timestamp of the TSA
- Another TickStampBlob with the AIK is created using the TSA's Timestamp a nonce

The first TickStampBlob is called "left" and the second "right" in a reference to
their position on a time-axis.

These three elements, with the TSA's certificate factored out, form
the synchronization token

~~~~ CDDL
TUDA-Synctoken = [
  left: TickStampBlob-Output,
  timestamp: TimeStampToken,
  right: TickStampBlob-Output,
]

TimeStampToken = bytes ; RFC 3161

TickStampBlob-Output = [
  currentTicks: TPM-CURRENT-TICKS,
  sig: bytes,
]

TPM-CURRENT-TICKS = [
  currentTicks: uint
  ? (
    tickRate: uint
    tickNonce: TPM-NONCE
  )
]
; Note that TickStampBlob-Output "right" can omit the values for
;   tickRate and tickNonce since they are the same as in "left"

TPM-NONCE = bytes .size 20
~~~~
{:cddl #sync-token title="TUDA-Sync element in CDDL"}

Required TPM functions:

<!-- TPM_TickStampBlob: -->
<!-- : explain various inputs and applications -->

~~~~ pseudocode
| dummyDigest = h'0000000000000000000000000000000000000000'
| dummyNonce = dummyDigest
|
| create_sync_token(AIKHandle, TSA) = {
|   ts_left = TPM_TickStampBlob(
|       keyHandle = AIK_Handle,      /*TPM_KEY_HANDLE*/
|       antiReplay = dummyNonce,     /*TPM_NONCE*/
|       digestToStamp = dummyDigest  /*TPM_DIGEST*/)
|
|   ts = TSA_Timestamp(TSA, nonce = hash(ts_left))
|
|   ts_right = TPM_TickStampBlob(
|       keyHandle = AIK_Handle,      /*TPM_KEY_HANDLE*/
|       antiReplay = dummyNonce,     /*TPM_NONCE*/
|       digestToStamp = hash(ts))    /*TPM_DIGEST*/
|
|   TUDA-SyncToken = [[ts_left.ticks, ts_left.sig], ts,
|                     [ts_right.ticks.currentTicks, ts_right.sig]]
|   /* Note: skip the nonce and tickRate field for ts_right.ticks */
| }

~~~~
{: #make-sync-token title="Creating the Sync-Token element"}


### RestrictionInfo

The attestation relies on the capability of the TPM to operate on restricted keys.
Whenever the PCR values for the machine to be attested change, a new restricted key
is created that can only be operated as long as the PCRs remain in their current state.

In order to prove to the Verifier that this restricted temporary key actually has
these properties and also to provide the PCR value that it is restricted, the TPM
command TPM_CertifyInfo is used. It creates a signed certificate using the AIK about
the newly created restricted key.

This token is formed from the list of:

- PCR list,
- the newly created restricted public key, and
- the certificate.

~~~~ CDDL
TUDA-RestrictionInfo = [Composite,
                        restrictedKey_Pub: Pubkey,
                        CertifyInfo]

PCRSelection = bytes .size (2..4) ; used as bit string

Composite = [
  bitmask: PCRSelection,
  values: [*PCR-Hash],
]

Pubkey = bytes ; may be extended to COSE pubkeys

CertifyInfo = [
  TPM-CERTIFY-INFO,
  sig: bytes,
]

TPM-CERTIFY-INFO = [
  ; we don't encode TPM-STRUCT-VER:
  ; these are 4 bytes always equal to h'01010000'
  keyUsage: uint, ; 4byte? 2byte?
  keyFlags: bytes .size 4, ; 4byte
  authDataUsage: uint, ; 1byte (enum)
  algorithmParms: TPM-KEY-PARMS,
  pubkeyDigest: Hash,
  ; we don't encode TPM-NONCE data, which is 20 bytes, all zero
  parentPCRStatus: bool,
  ; no need to encode pcrinfosize
  pcrinfo: TPM-PCR-INFO,        ; we have exactly one
]

TPM-PCR-INFO = [
    pcrSelection: PCRSelection; /* TPM_PCR_SELECTION */
    digestAtRelease: PCR-Hash;  /* TPM_COMPOSITE_HASH */
    digestAtCreation: PCR-Hash; /* TPM_COMPOSITE_HASH */
]

TPM-KEY-PARMS = [
  ; algorithmID: uint, ; <= 4 bytes -- not encoded, constant for TPM1.2
  encScheme: uint, ; <= 2 bytes
  sigScheme: uint, ; <= 2 bytes
  parms: TPM-RSA-KEY-PARMS,
]

TPM-RSA-KEY-PARMS = [
  ; "size of the RSA key in bits":
  keyLength: uint
  ; "number of prime factors used by this RSA key":
  numPrimes: uint
  ; "This SHALL be the size of the exponent":
  exponentSize: null / uint / biguint
  ; "If the key is using the default exponent then the exponentSize
  ; MUST be 0" -> we represent this case as null
]

~~~~
{:cddl #key-token title="TUDA-Key element in CDDL"}


Required TPM functions:

~~~~ pseudocode
| dummyDigest = h'0000000000000000000000000000000000000000'
| dummyNonce = dummyDigest
|
| create_Composite
|
| create_restrictedKey_Pub(pcrsel) = {
|   PCRInfo = {pcrSelection = pcrsel,
|              digestAtRelease = hash(currentValues(pcrSelection))
|              digestAtCreation = dummyDigest}
|   / * PCRInfo is a TPM_PCR_INFO and thus also a TPM_KEY */
|
|   wk = TPM_CreateWrapKey(keyInfo = PCRInfo)
|   wk.keyInfo.pubKey
| }
|
| create_TPM-Certify-Info = {
|   CertifyInfo = TPM_CertifyKey(
|       certHandle = AIK,          /* TPM_KEY_HANDLE */
|       keyHandle = wk,            /* TPM_KEY_HANDLE */
|       antiReply = dummyNonce)    /* TPM_NONCE */
|
|   CertifyInfo.strip()
|   /* Remove those values that are not needed */
| }
~~~~
{: #make-pubkey title="Creating the pubkey"}


### Measurement Log {#mlog}

Similarly to regular attestations, the Verifier needs a way to reconstruct the PCRs'
values in order to estimate the trustworthiness of the device. As such, a list of
those elements that were extended into the PCRs is reported. Note though that for
certain environments, this step may be optional if a list of valid PCR configurations
exists and no measurement log is required.

~~~~ CDDL
TUDA-Measurement-Log = [*PCR-Event]
PCR-Event = [
  type: PCR-Event-Type,
  pcr: uint,
  template-hash: PCR-Hash,
  filedata-hash: tagged-hash,
  pathname: text; called filename-hint in ima (non-ng)
]

PCR-Event-Type = &(
  bios: 0
  ima: 1
  ima-ng: 2
)

; might want to make use of COSE registry here
; however, that might never define a value for sha1
tagged-hash /= [sha1: 0, bytes .size 20]
tagged-hash /= [sha256: 1, bytes .size 32]
~~~~

### Implicit Attestation {#impa}

The actual attestation is then based upon a TickStampBlob using the restricted
temporary key that was certified in the steps above. The TPM-Tickstamp is executed
and thereby provides evidence that at this point in time (with respect to the TPM
internal tick-session) a certain configuration existed (namely the PCR values associated
with the restricted key). Together with the synchronization token this tick-related
timing can then be related to the real-time clock.

This element consists only of the TPM_TickStampBlock with no nonce.

~~~~ CDDL
TUDA-Verifytoken = TickStampBlob-Output
~~~~
{:cddl #verify-token title="TUDA-Verify element in CDDL"}

Required TPM functions:

~~~~ pseudocode
| imp_att = TPM_TickStampBlob(
|     keyHandle = restrictedKey_Handle,     /*TPM_KEY_HANDLE*/
|     antiReplay = dummyNonce,              /*TPM_NONCE*/
|     digestToStamp = dummyDigest)          /*TPM_DIGEST*/
|
| VerifyToken = imp_att
~~~~
{: #make-verifytoken title="Creating the Verify Token"}


### Attestation Verification Approach

The seven TUDA information elements transport the essential content that is required to enable
verification of the attestation statement at the Verifier. The following listings illustrate
the verification algorithm to be used at the Verifier in
pseudocode. The pseudocode provided covers the entire verification
task.
If only a subset of TUDA elements changed (see {{updatecycles}}), only
the corresponding code listings need to be re-executed.

~~~~ pseudocode
| TSA_pub = verifyCert(TSA-CA, Cert.TSA-Cert)
| AIK_pub = verifyCert(AIK-CA, Cert.AIK-Cert)
~~~~
{: #verify-Certs title="Verification of Certificates"}


~~~~ pseudocode
| ts_left = Synctoken.left
| ts_right = Synctoken.right
|
| /* Reconstruct ts_right's omitted values; Alternatively assert == */
| ts_right.currentTicks.tickRate = ts_left.currentTicks.tickRate
| ts_right.currentTicks.tickNonce = ts_left.currentTicks.tickNonce
|
| ticks_left = ts_left.currentTicks
| ticks_right = ts_right.currentTicks
|
| /* Verify Signatures */
| verifySig(AIK_pub, dummyNonce || dummyDigest || ticks_left)
| verifySig(TSA_pub, hash(ts_left) || timestamp.time)
| verifySig(AIK_pub, dummyNonce || hash(timestamp) || ticks_right)
|
| delta_left = timestamp.time -
|     ticks_left.currentTicks * ticks_left.tickRate / 1000
|
| delta_right = timestamp.time -
|     ticks_right.currentTicks * ticks_right.tickRate / 1000
~~~~
{: #verify-sync title="Verification of Synchronization Token"}


~~~~ pseudocode
| compositeHash = hash_init()
| for value in Composite.values:
|     hash_update(compositeHash, value)
| compositeHash = hash_finish(compositeHash)
|
| certInfo = reconstruct_static(TPM-CERTIFY-INFO)
|
| assert(Composite.bitmask == ExpectedPCRBitmask)
| assert(certInfo.pcrinfo.PCRSelection == Composite.bitmask)
| assert(certInfo.pcrinfo.digestAtRelease == compositeHash)
| assert(certInfo.pubkeyDigest == hash(restrictedKey_Pub))
|
| verifySig(AIK_pub, dummyNonce || certInfo)
~~~~
{: #verify-restrictioninfo title="Verification of Restriction Info"}


~~~~ pseudocode
| for event in Measurement-Log:
|     if event.pcr not in ExpectedPCRBitmask:
|         continue
|     if event.type == BIOS:
|         assert_whitelist-bios(event.pcr, event.template-hash)
|     if event.type == ima:
|         assert(event.pcr == 10)
|         assert_whitelist(event.pathname, event.filedata-hash)
|         assert(event.template-hash ==
|                hash(event.pathname || event.filedata-hash))
|     if event.type == ima-ng:
|         assert(event.pcr == 10)
|         assert_whitelist-ng(event.pathname, event.filedata-hash)
|         assert(event.template-hash ==
|                hash(event.pathname || event.filedata-hash))
|
|     virtPCR[event.pcr] = hash_extend(virtPCR[event.pcr],
|                                      event.template-hash)
|
| for pcr in ExpectedPCRBitmask:
|     assert(virtPCR[pcr] == Composite.values[i++]
~~~~
{: #verify-measurementlog title="Verification of Measurement Log"}


~~~~ pseudocode
| ts = Verifytoken
|
| /* Reconstruct ts's omitted values; Alternatively assert == */
| ts.currentTicks.tickRate = ts_left.currentTicks.tickRate
| ts.currentTicks.tickNonce = ts_left.currentTicks.tickNonce
|
| verifySig(restrictedKey_pub, dummyNonce || dummyDigest || ts)
|
| ticks = ts.currentTicks
|
| time_left = delta_right + ticks.currentTicks * ticks.tickRate / 1000
| time_right = delta_left + ticks.currentTicks * ticks.tickRate / 1000
|
| [time_left, time_right]
~~~~
{: #verify-attestation title="Verification of Attestation Token"}

## IE Generation Procedures for TPM 2.0 {#tpm2}

The pseudocode below includes general operations that are conducted as specific TPM commands:

* hash() : description TBD
* sig() : description TBD
* X.509-Certificate() : description TBD

These represent the output structure of that command in the form of a byte string value.

### AIK and AIK Certificate {#aik2}

Attestations are based upon a cryptographic signature performed by the TPM using
a so-called Attestation Identity Key (AIK). An AIK has the properties that it cannot
be exported from a TPM and is used for attestations. Trust in the AIK is established
by an X.509 Certificate emitted by a Certificate Authority. The AIK certificate is
either provided directly or via a so-called PrivacyCA {{AIK-Enrollment}}.

This element consists of the AIK certificate that includes the AIK's public key used
during verification as well as the certificate chain up to the Root CA for validation
of the AIK certificate itself.

~~~~ pseudocode
TUDA-Cert = [AIK-Cert, TSA-Cert]; maybe split into two for SNMP
AIK-Certificate = X.509-Certificate(AIK-Key,Restricted-Flag)
TSA-Certificate = X.509-Certificate(TSA-Key, TSA-Flag)
~~~~
{:pseudo #cert-token2 title="TUDA-Cert element for TPM 2.0"}

### Synchronization Token

The synchronization token uses a different TPM command, TPM2 GetTime() instead of TPM TickStampBlob().  The TPM2 GetTime() command contains the clock and time information of the TPM. The clock information is the equivalent of TUDA v1's tickSession information.

~~~~ pseudocode
TUDA-SyncToken = [
  left_GetTime = sig(AIK-Key,
                     TimeInfo = [
                       time,
                       resetCount,
                       restartCount
                     ]
                    ),
  middle_TimeStamp = sig(TSA-Key,
                         hash(left_TickStampBlob),
                         UTC-localtime
                        ),
  right_TickStampBlob = sig(AIK-Key,
                            hash(middle_TimeStamp),
                            TimeInfo = [
                              time,
                              resetCount,
                              restartCount
                            ]
                           )
]
~~~~
{:pseudo #sync-token2 title="TUDA-Sync element for TPM 2.0"}

### Measurement Log

The creation procedure is identical to {{mlog}}.

~~~~ pseudocode
Measurement-Log = [
  * [ EventName,
      PCR-Num,
      Event-Hash ]
]
~~~~
{:pseudo #log-token2 title="TUDA-Log element for TPM 2.0"}

### Explicit time-based Attestation

The TUDA attestation token consists of the result of TPM2_Quote() or a set of TPM2_PCR_READ followed by a TPM2_GetSessionAuditDigest. It proves that --- at a certain point-in-time with respect to the TPM's internal clock --- a certain configuration of PCRs was present, as denoted in the keys restriction information.

~~~~ pseudocode
TUDA-AttestationToken = TUDA-AttestationToken_quote / TUDA-AttestationToken_audit

TUDA-AttestationToken_quote = sig(AIK-Key,
                                  TimeInfo = [
                                    time,
                                    resetCount,
                                    restartCount
                                  ],
                                  PCR-Selection = [ * PCR],
                                  PCR-Digest := PCRDigest
                                 )

TUDA-AttestationToken_audit = sig(AIK-key,
                                  TimeInfo = [
                                    time,
                                    resetCount,
                                    restartCount
                                  ],
                                  Session-Digest := PCRDigest
                                 )
~~~~
{:pseudo #attest-token2 title="TUDA-Attest element for TPM 2.0"}

### Sync Proof

In order to proof to the Verifier that the TPM's clock was not 'fast-forwarded' the result of a TPM2_GetTime() is sent after the TUDA-AttestationToken.

~~~~ pseudocode
TUDA-SyncProof = sig(AIK-Key,
                     TimeInfo = [
                       time,
                       resetCount,
                       restartCount
                     ]
                    ),
~~~~
{:pseudo #prrof-token2 title="TUDA-Proof element for TPM 2.0"}

#  Acknowledgements
{: numbered="no"}

<!--  LocalWords:  TPM AIK TUDA uptime PCR Verifier Attester CoRE RTC
 -->
<!--  LocalWords:  RESTCONF pseudocode disambiguates TSA PCRs RoT
 -->
<!--  LocalWords:  Attester's retransmitting Verifiers Timestamp
 -->
<!--  LocalWords:  TickStampBlob Attesters parallelization tickstamps
 -->
<!--  LocalWords:  trustable tickstamp cryptoprocessor BootLoader
 -->
<!--  LocalWords:  PCRInfo keyInfo
 -->
