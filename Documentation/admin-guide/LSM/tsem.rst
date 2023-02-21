====
TSEM
====

	"This is the story of the wine of Brule, and it shows what
	 men love is never money itself but their own way, and
	 that human beings love sympathy and pageant above all
	 things."
				- Hilaire Belloc
				  The Path to Rome

TSEM is the Trusted Security Event Modeling system.  Conceptually it
can be thought of as an integration of system integrity measurement
and mandatory access controls.

The design and implementation of TSEM was inspired by the notion that
the security behavior of a platform, or a workload, like all other
physical phenomenon, can be mathematically modeled.

Security, is at once, both a technical and economic problem.  One of
the objectives of TSEM is to address inherent and structural economic
barriers to security, by introducing technology that reduces the skill
and time needed to implement a level of security, equivalent to what
can be achieved by mandatory access controls, through unit testing of
an application stack.

A second objective, is to reduce the skill, complexity and
infrastructure needed to create remotely attestable platforms and/or
workloads.

To achieve these objectives, TSEM implements the concept of a modeling
domain, nee namespace, that reduces the complexity of a security model
and allows it to be scoped to the level of a single process or a
container.

TSEM is the Linux kernel component of a security concept introduced by
the Quixote Project, the notion of a Trust Orchestration System (TOS).
The concept of a TOS is to have a system with a minimal Trusted
Computing Base (TCB) that supervises and maintains subordinate
modeling domains/namespaces in a known trust state.

TSEM is implemented as a Linux Security Module (LSM) and is designed
to be self-contained with little or no dependency on kernel
infrastructure, other than the LSM hooks themselves.  It can be
stacked in any order with existing LSM's.  Integrity modeling of
extended attributes would require that TSEM be earlier in the LSM call
chain then any LSM's that consume the modeled attributes.

In addition, TSEM implements its equivalent of mandatory access
controls, without a requirement for extended attributes, filesystem
labeling or the need to protect filesystem metadata against offline
attack.

TBDHTTRAD
=========

A quick summary for those interested in experimenting with trust
orchestration and security modeling but are constrained by: 'Too Busy
Don't Have Time To Read Any Documentation'.

Access to the securityfs filesystem is required by the trust
orchestrators.  The filesystem should be automatically mounted by
major distributions, if not, the following command can be used to
mount the filesystem:

mount -t securityfs securityfs /sys/kernel/security

A kernel with TSEM support in its list of enabled LSM's must be
available for use.  A TSEM enabled kernel will have the tsem keyword
in the following file:

/sys/kernel/security/lsm

The trust orchestrators access the TSEM management filesystem through
the following directory in the securityfs filesystem:

/sys/kernel/security/tsem

For experimentation, or integrating TSEM modeling into a CI
development workflow, modeling can be restricted to subordinate
modeling domains by booting a kernel with the following kernel
command-line option:

tsem_mode=1

The Quixote trust orchestration utilities either need to be built or
the statically compiled demonstration system needs to be installed.
Source for the userspace utilities and compiled sample programs are
available at the following location:

ftp://ftp.enjellic.com/pub/Quixote

After installing the utilities, two shell sessions will be needed with
root privileges in each shell.

The following directories need to be in the PATH variable of each shell:

/opt/Quixote/sbin
/opt/Quixote/bin

Execute the following command to start a process in an independent
modeling domain/namespace with the security modeling being done in the
kernel:

quixote -P -c test -o test.model

In the second shell session, run the following command to display the
security execution trajectory of the model:

quixote-console -p test -T

In the shell session provided by the trust orchestrator, run the
following command:

grep SOME_STRING /etc/passwd

Then exit the shell.

The orchestrator will indicate that the security model definition has
been written to the test.model file.

Run the following command to execute a shell in an enforced security
model obtained from the previous session:

quixote -P -c test -m test.model -e

In the shell that is provided, run the following command:

cat /etc/passwd

The command will fail.

Running the following command in the second shell session will output
forensics on the command that failed:

quixote-console -p test -F

Executing additional commands in the trust orchestrated shell will
cause additional entries to be added to the forensics trajectory.

The test can be repeated using the quixote-us trust orchestrator.
This test will model the security domain/namespace in a userspace
process rather than in the kernel based modeling agent.

Mandatory Access Controls
=========================

	"If I have seen further it is by standing on the shoulders of
	 Giants."
				- Sir Isaac Newton

It is assumed that astute readers will be familiar with classic
subject/object based mandatory access controls; or at least astute
enough to use a search engine to develop a modicum of secundem artem
in the discipline.

Very simplistically, subject/object based mandatory access controls
can be thought of as being implemented with a two dimensional access
vector matrix, with some type of a description of a process (subject)
on one axis and a description of a data sync/source (object),
typically an inode, on the second axis.  The descriptions are
commonly referred to as subjects and objects.

A security policy is developed that assigns a boolean value for each
element of the matrix that specifies whether or not permission should
be granted for the subject to access the object.

These schemes are frequently referred to as 'mandatory access
controls', since only the kernel has the ability to implement the
labeling and decision process.  In these systems, the root or
administrative user has no ability to affect the kernel decision
making with respect to whether or not permission is granted or denied.

These systems were derived from governmental and military information
classification systems and are capable of delivering security
guarantees appropriate to classified and high sensitivity assets.  The
delivery of these security guarantees comes with it a reputation for
complexity and fragility.

Development of a system wide security policy is a complex process and
administration of such systems is frequently done in an iterative
fashion.  The system is monitored for permission denials with
modifications to correct these false denials folded back into the
policy.  In many cases, mandatory access control systems are run in
warning rather than enforcing mode and used as an indicator for
potential security violations.

One of the additional challenges is that the integrity of labels is
fundamental to the ability of these systems to deliver their security
guarantees.  This requires that the labeling process be conducted
under security controlled conditions with the labels protected against
offline modification by cryptographic integrity guarantees.

Mandatory access controls had their origin in centralized multi-user
platforms, and before the now, widely accepted strategy of using
resource compartmentalization (namespaces) to isolate applications
from each other and the system at large.  A legitimate technical
argument can be made as to whether or not enforcement of a system wide
security policy is suitable for these environments.

At the other end of the spectrum, in embedded systems, structural
economic barriers incent very little attention to security, where time
to market is the primary goal.  These systems are pushed into the
field, many time for multi-year operational lifetimes, with little
prospect for upgrades or any notion of an iterative tuning process of
a security policy.

Security Event Modeling
=======================

	"We can no longer speak of the behavior of the particle
	 independently of the process of observation. As a final
	 consequence, the natural laws formulated mathematically in
	 quantum theory no longer deal with the elementary particles
	 themselves but with our knowledge of them. Nor is it any
	 longer possible to ask whether or not these particles exist in
	 space and time objectively ... When we speak of the picture of
	 nature in the exact science of our age, we do not mean a
	 picture of nature so much as a picture of our relationships
	 with nature.  ...Science no longer confronts nature as an
	 objective observer, but sees itself as an actor in this
	 interplay between man and nature. The scientific method of
	 analysing, explaining and classifying has become conscious of
	 its limitations, which arise out of the fact that by its
	 intervention science alters and refashions the object of
	 investigation. In other words, method and object can no longer
	 be separated."
				- Werner Karl Heisenberg

Security Event Modeling (SEM), is an alternative strategy to implement
the security guarantees of mandatory access and integrity controls, in
a manner that is consistent with emerging application development
strategies such as namespaces and continuous integration testing.

As was noted at the start of this document, the premise for SEM is
that the security behavior of a platform, or alternatively a workload,
can be modeled like any other physical phenomenon in science and
engineering.

Inspiration for this came from the primary TSEM author/architect
having trained as a quantum chemist, conducting very early research in
the development of multi-scale modeling strategies for molecules of
size to be of interest to pharmaceutical intents.

SEM is premised on the theory that kernel security architects have
instrumented the LSM security event hooks to be called from all
locations, with appropriate descriptive parameters, that are relevant
to the security posture of the kernel.  With respect to modeling, the
security event hooks are conceptualized as representing the
independent variables of a basis set that yields a functional
definition for the security state of an execution trajectory.

SEM can be framed in the context of classic subject/object mandatory
access controls, by the notion that a unique identity can be generated
for each element of an access vector matrix, rather than a boolean
value.  In SEM, a security execution trajectory is defined by the set
of points in an access vector matrix that a process hierarchy
(workload) references.  This execution trajectory produces a vector of
identities, whose sum in an appropriate form, yields a functional
definition of the security state of the system.

Two subordinate identities are combined to yield a security event
state point.  These subordinate identities are referred to as the
Context Of Execution (COE) and the CELL, which are conceptually
similar to the subject and objects in mandatory access control.  The
COE identity is derived from the parameters that describe the security
relevant characteristics of a process, while the CELL value is derived
from the parameters used by a security event hook to describe the
characteristics of the event.

A security policy is implemented by a modeling algorithm that
translates COE and CELL event parameters into their respective
identities.  Different security policies can be developed by modifying
how the modeling algorithm utilizes the COE and CELL characteristics.

Since the security policy is implemented with a modeling algorithm, a
single platform can support multiple and arbitrary security policies.
The equivalent of a resource namespace in SEM is referred to as a
modeling domain and can be conceptualized as a mandatory access
control or integrity namespace.

The formation of the security event state points from existing kernel
parameters eliminates the need for the use of extended attributes to
hold security label definitions.  In SEM, a cryptographically signed
security model definition, designed to be interpreted by a modeling
engine, becomes the bearer's token for the security of the modeling
target, rather than information encoded in filesystem security
attributes.

Trusted Security Event Modeling
===============================

	"Do you see over yonder, friend Sancho, thirty or forty
	 hulking giants?  I intend to do battle with them and slay
	 them."
				- Don Quixote

In TSEM, the modeling algorithm is implemented in an entity known as a
Trusted Modeling Agent (TMA), in a 'trusted' environment where
modeling is immune from modification or alteration by any activity on
the platform or in a workload.  The notion of a TMA provides a
framework for next generation security co-processors that extend
beyond what is defined by the concept of a Trusted Platform Module
(TPM).

In addition to providing an attestation of an execution trajectory, a
TMA, in contrast to a TPM, has the ability to advise an operating
system on whether or not an event being modeled is consistent with the
security policy that is being enforced.  In this manner, it introduces
a prospective rather than a retrospective trust model.

TSEM is designed to support Trust Orchestration Systems (TOS).  In a
TOS, the trust orchestrators are supervisory programs that run
workloads in independent modeling domains, enforcing a workload
specific security model.  Each trust orchestrator is paired with a
'trusted partner TMA', that implements the workload specific modeling
algorithm.

The root of trust for a workload modeling domain is based on where the
TMA instance is implemented.  As an example, the Quixote TOS
implementation currently offers orchestrators for the following TMA
execution localities:

- Kernel.

- Userspace process.

- SGX enclave.

- Xen stub domain.

- Micro-controller.

This partitioning of trust results in the concept of security domains
being referred to as internally or externally modeled.  A TMA
implementation run in the kernel is referred to as an internally
modeled domain; TMA's run outside of the kernel are referred to as
externally modeled domains.

The TMA, regardless of locality, is responsible for processing the
characteristics that describe a security event, computing the identity
for the COE and CELL and then combining these two identities to create
a security event state point.  With respect to modeling theory, the
security event state point is a task specific coefficient representing
the event in a security model.

TSEM is dispassionate with respect to the type of algorithm that is
implemented.  The processing of the security event characteristics and
their conversion to state points, is driven by the security
model/policy that will be implemented for the workload.  It is
assumed, that security model algorithms will embrace various
approximations, and perhaps even stochastic reasoning and machine
learning methods, as new security models are developed in response to
specific workload, platform and device requirements.

A security model, to be enforced by a trust orchestrator, is
implemented by providing the TMA with a set of security state points
that are to be observed.  A TMA processes the characteristics of a
security event and converts the characteristics to a state point that
is evaluated against the state points provided to the TMA as the
reference security behavior of a workload.

A security event that translates to one of the provided 'good' points,
will cause the TMA to indicate to the trust orchestrator that the
process is to be allowed to run as a trusted process.  A security
event that does not map to a known good point, results in the trust
orchestrator designating that the process be run as an untrusted
process.

Trust orchestrators and their associated TMA's, are designed to
support signed security models.  This results in the elimination of
the requirement to verify or appraise extended attributes and other
measures currently required to protect trusted security systems
against offline attacks.

The use of a cryptographic hash function to generate the security
state points results in the definition of very specific security
behaviors, that are sensitive to any variation in their
characteristics.  Any offline modifications to files will result in a
security state point that is inconsistent with a signed model provided
to a TMA.

In order to support the development of TSEM based security models, a
TMA is designed to run in one of three separate modes, referred to as
follows:

- Free modeling.

- Sealed.

- Enforcing.

In a free modeling configuration, the TMA adds the security state
point for the characteristics of a security event to the current set
of known good states.  In addition, the description of the security
event is retained as a member of the security execution trajectory for
the model.  This mode is used, in combination with unit testing of a
workload, to generate a security model for subsequent enforcement.

Placing a TMA in 'sealed' mode implies that any subsequent security
events, that do not map into a known security state point, are to be
considered 'forensic' violations to the security state of the model.
A forensics mapping event does not cause the initiating process to be
placed in untrusted mode; it is designed to provide the ability to
either fine tune a model or provide early warning of a potential
attempt to subvert the security status of a workload.

Placing a TMA model in 'enforcing' status implies that the model is in
a sealed state and any subsequent violations to the model will result
in a violating process being placed in untrusted status.  The
characteristics of the violating event will be registered in the
forensics trajectory for the model for use in subsequent evaluation of
the violating event and/or model refinement.

Process and Platform Trust Status
=================================

A fundamental concept in TSEM is the notion of providing a precise
definition for what it means for a platform or workload to be trusted.
A trusted platform or workload is one where there has not been an
attempt by a process to execute a security relevant event that does
not map into a known security state point.

The process trust status is a characteristic of the process that is
passed to any subordinate processes that are descendants of that
process.  Once a process is tagged as untrusted, that characteristic
cannot be removed from the process.  In a 'fruit from the poisoned
vine' paradigm, all subordinate processes created by an untrusted
process are untrusted as well.

On entry into each TSEM security event handler, the trust status of a
process is checked before an attempt to model the event is made.  An
attempt to execute a security event by an untrusted process will cause
the event, and its characteristics, to be logged.  The return status
of the hook will be determined by the enforcement state of the model.
A permission denial is only returned if the TMA is running in
enforcing mode.

If the platform running the TSEM LSM has a TPM, the hardware aggregate
value is computed at the time that TSEM is initialized.  This hardware
aggregate value is the linear extension sum over Platform
Configuration Registers (PCR's) 0 through 7.  This is the same
aggregate value that is computed by the Integrity Measurement
Architecture (IMA) and is the industry standard method of providing an
evaluation measurement of the hardware platform state.

Internally model domains have the hardware aggregate measurement
included as the first state point in the security model.  Externally
modeled domains export the hardware aggregate value to the TMA for
inclusion as the first state point of the model maintained by the TMA.

The root modeling domain extends each security state point into PCR
11.  This allows hardware based TSEM measurements to coexist with IMA
measurement values.  This hardware measurement value can be used to
attest to the security execution trajectory that the root model
maintains.

TSEM operates under the assumption that the root domain will be a
minimum Trusted Computing Base implementation that will only be
running trust orchestrators.  Subordinate modeling domains are
designed, deliberately, to be non-hierarchical, so as to decrease
model complexity in the subordinate domains in order to support a
single functional value describing the security state of a security
domain.

The Linux TSEM Implementation
=============================

	"Sometimes the questions are complicated and the answers are
	 simple."
				- Dr. Seuss

The Linux TSEM implementation is deliberately simplistic and consists
of the following two generic components:

- Modeling namespace and security event export functionality.

- Internal trusted modeling agent.

The modeling namespace and export functionality is designed to be
generic infrastructure that allows security domains to be created that
are either internally or externally modeled.  The TSEM implementation
does not pose any constraints on what type of modeling can or should
be implemented in these domains.

On the theory that security event handlers represent all of the
security relevant points in the kernel, any security or integrity
model can be implemented using the TSEM infrastructure.  For example,
basic IMA functionality could be implemented by a TMA that maps the
digests of files accessed, or mapped executable, by the root user as
the security state points.

A primary intent of the Linux TSEM implementation is to provide a
generic method for implementing security policy in userspace rather
than the kernel.  This is consistent with what has been the historic
understanding in Linux architecture, that policy decisions should be
delegated, when possible, to userspace rather than to kernel based
implementations.

The model is extremely simplistic; a TMA interprets a security event
and its characteristics and advises whether or not the kernel should
designate the process as trusted or untrusted after event processing
is complete.

The following sections discuss various aspects of the infrastructure
used to implement this architecture.

Internal vs external modeling
-----------------------------

When a TSEM modeling domain is created, a designation is made as to
whether the domain is to be internally or externally modeled.

In an internally modeled domain, the security event handlers pass the
event type and its characteristics to the designated internal trusted
modeling agent.  The agent provides the permission value for the
security event handler to return as the result of the event and sets
the trust status of the process executing the event.

In an externally modeled domain, the event type and parameters are
exported to userspace for processing by a trust orchestrator with an
associated TMA.  The trust orchestrator communicates the result of the
modeling back to the kernel to support the setting of the process
trust status.

This model poses a limitation to the ability of TSEM to model some
security events.  This is secondary to the fact that some event
handlers (LSM hooks) are called from a non-sleeping context, as a
result the process cannot be scheduled.  This is particularly the case
with the task based hooks, since they are typically called with the
tasklist lock held.

This limitation is also inherent to the root model that extends the
security state points into TPM PCR 11, secondary to the fact that the
process invoking the security event hook will be scheduled away while
the TPM transaction completes.

Addressing this problem directly requires a consideration of the
context from which the security event handlers are being called.
Subsequent implementations of TSEM will include a mechanism for
asynchronous deferral of model processing, until when and if, a review
of the call context would be considered worthwhile by the LSM
community.

Event handlers that cannot be directly modeled, still consider, on
entry, whether or not they are being called by an trusted or untrusted
process.  As a result, an untrusted process will cause a non-modeled
event to return a permissions violation in enforcing mode, even if the
security event cannot be directly modeled.

Security event modeling typically traps violations of trust by a COE
with unmodeled characteristics that is attempting to access/execute a
file or map memory as executable; or by a COE with known
characteristics attempting to access or execute a CELL not prescribed
by a model.  As a result, the impact of the ability to not directly
model these events is lessened.

Explicit vs generic modeling
----------------------------

In addition to the COE characteristics, TMA's have the ability to
include the parameters that characterize the CELL of the security
event into the generation of the security state point for the event.
The inclusion of the CELL characteristics is considered explicit
modeling of the event.

TMA's also have the ability to consider only the COE characteristics
and the type of the event.  This is referred to as generic modeling of
the event.

In the current Linux TSEM implementation, the security event handlers
differentiate, primarily due to code maturity reasons, some events to
be generically modeled.  For these events, in addition to the COE
characteristics and task identity, a default CELL value is used in the
computation of the security state point.

As was noted in the section on 'internal vs external modeling', the
most common violation of trust is the initial execution of a binary or
access to a file.  The inclusion of events, as generically modeled,
allows the capture of security behaviors that are inconsistent with a
proscribed security model, even if full characterization of the event
is not implemented.

In the following ABI document:

Documentation/ABI/testing/tsemfs

The /sys/fs/tsem/trajectory entry documents parameters that are
available for modeling by both internally and externally modeled
domains.

Event modeling
--------------

TSEM security event modeling is based on the following functional
definition for a security state point:

Sp = SHA256(SHA256(EVENT_ID) || TASK_ID || SHA256(COE) || SHA256(CELL))

	Where:
		||       = Concatenation operator.

		EVENT_ID = ASCII name of event.

		TASK_ID  = 256 bit identity of the process executing
			   the security event.

		COE      = Characteristics of the context of execution
			   of the event.

		CELL	 = Characteristics of the object that the
			   security event is acting on.

Workload or platform specific security point state definitions are
implemented by a TMA using whatever COE or CELL characteristics that
are considered relevant in determining whether or not a process should
be considered trusted or untrusted.

The TASK_ID component of the function above is important with respect
to the generation of the security state points.  The notion of a task
identity serves to link the concepts of system integrity and mandatory
access control.

The TASK_ID is defined by the following function:

TASK_ID = SHA256(SHA256(EVENT) || NULL_ID || SHA256(COE) || SHA256(CELL))

	Where:
		||        = Concatenation operator.

		EVENT	  = The string "bprm_set_creds".

		NULL_ID	  = A buffer contain 32 null bytes (0x00).

		COE	  = Characteristics of the context of execution
			    calling the bprm_creds_for_exec LSM hook.

		CELL	  = The characteristics of the file provided
			    by the linux_binprm structure passed to
			    the security hook.

An informed reader will quickly conclude, correctly, that the TASK_ID
function generates an executable specific security state point for the
bprm_creds_for_exec security hook.  The function is the same as the
standard security point; with the exception that the task identity is
replaced with a 'null id', one that consists of 32 null bytes.

One of the CELL characteristics used in the computation of the task
identity is the digest of the executable file.  Modifying an
executable, or attempting to execute a binary not considered in the
security model, will result in an alteration of the task identity that
propagates to the generation of invalid state points.

The task identity is saved in the TSEM specific task structure and is
used to compute the state points for any security events that the task
subsequently executes.  As noted in the previous paragraph,
incorporating the TASK_ID into the computation of security state
points results in the points becoming executable specific.  This
affords a very degree of specificity with respect to the security
models that can be implemented.

As was demonstrated in the TBDHTTRAD section, TSEM will discriminate
the following commands as different events/coefficients in a security
model:

cat /etc/shadow

grep something /etc/shadow

while read input
do
	echo $input;
done < /etc/shadow

An important, and perhaps subtle issue to note, is how these events
result in the change of process trust status.  In the first two cases,
if access to the /etc/shadow file is not permitted by the operative
security model, the cat and grep process will become untrusted.

In the third example, the shell process itself would become untrusted.
This would cause any subsequent attempts to execute a binary to be
considered untrusted events, even if access to the binary is a
permitted point in the model.

Since the modeling operates at the level of mandatory access controls,
these permission denials would occur even if the process is running
with root privilege levels.  This is secondary to the notion that
security and trust status are invested in the trust orchestrator and
ultimately the TMA.

From a hardware perspective, this is important with respect to the
notion of a TMA being a model for a successor to the TPM.  From a
system trust or integrity perspective, a TPM is designed to provide a
retrospective assessment of the actions that have occurred on a
platform.  A verifying party uses the TPM event log and a PCR based
summary measurement, to verify what actions have occurred on the host,
in order to allow a determination of whether or not the platform
should be 'trusted'.

In contrast, a TSEM/TMA based system enforces, on a real time basis,
that a platform or workload remains in a trusted state.  Security
relevant actions cannot be conducted unless the TMA authorizes the
actions as being trusted.

This is particularly important with respect to embedded systems.  A
TPM based architecture would not prevent a system from having its
trust status altered.  Maintaining the system in a trusted state would
require attestation polling of the system, and presumably, executing
actions if the platform has engaged in untrusted behavior.

Conversely, a trust orchestrated software implementation enforces that
a system or workload remain in a security/trust state that it's
security model was unit tested to.

Security model functional definitions
-------------------------------------

Previously, classic trusted system implementations supported the
notion of the 'measurement' of the system.  The measurement is the
value of a linear extension function of all the security relevant
actions recorded by a trust measurement system such as IMA.

In TPM based trust architectures, this measurement is maintained in a
PCR.  A measurement value is submitted to the TPM that extends the
current measurement using the following formula:

MEASUREMENT = HASH(CURRENT || NEW)

	Where:
		||	    = Concatenation operator.

		MEASUREMENT = The new measurement value to be maintained
			      in the register for the system.

		CURRENT     = The current measurement value.

		NEW	    = A new measurement value to be added to
			      the current measurement.

		HASH	    = A cryptographic hash function.

In TPM1 based systems the HASH function was SHA1.  Due to well
understood security concerns about the cryptographic vitality of this
function, TPM2 based systems provide additional HASH functions with
stronger integrity guarantees, most principally SHA related functions
with longer digest values such as SHA256, SHA384 and SM3.

The use of a cryptographic function produces a non-commutative sum
that can be used to verify the integrity of a series of measurements.
With respect to security modeling theory, this can be thought of as a
'time-dependent' measurement of the system.  Stated more simply, the
measurement value is sensitive to the order in which the measurements
were made.

In systems such as IMA, the measurement value reflects the sum of
digest values of what are considered to be security critical entities,
most principally, files that are accessed based on various policies.

In TSEM based TMA's, the measurement of a modeling domain is the sum
of the security state points generated by the operative security model
being enforced.  As previously noted, on systems with a TPM, the root
modeling domain measurement is maintained in PCR 11.

The challenge associated with classic integrity measurements is the
time dependent nature of using a non-commutative summing function.
The almost universal embrace of SMP based hardware architectures and
standard kernel task scheduling makes the measurement values
non-deterministic.  This requires a verifying party to evaluate an
event log, verified by a measurement value, to determine whether or
not it is security appropriate.

TSEM addresses this issue by implementing a strategy designed to
produce a single functional value that represents the security state
of a model.  This allows a TMA to attest to the trust/security status
of a platform or workload by signing this singular value and
presenting it to a verifying party.

In TSEM nomenclature, this singular value is referred to as the
'state' of the model.  The attestation model is to use trust
orchestrators to generate the state value of a workload by unit
testing.  This state value can be packaged with a utility or container
to represent a summary trust characteristic that can be attested by a
TMA, eliminating the need for a verifying partner to review and verify
an event log.

TMA's implement this architecture by maintaining a single instance
vector of all the set of security model state points that have been
generated.  A state measurement is generated by sorting the vector in
big-endian hash format and then generating a standard measurement
digest over this new vector.

Any security event that generates an associated state point that is
not in the model will resulted in a perturbed state function value.
That perturbed value would be interpreted by a verifying party as an
indication of an untrusted system.

Since the TMA maintains the security event descriptions in time
ordered form the option to provide a classic event log and measurement
are preserved and available.  Extensive experience in the development
of TSEM modeled systems has demonstrated the superiority of state
value interpretation over classic measurement schemes.

A TMA may choose to incorporate a 'base nonce' into a security model
that is is implementing, this based nonce is designed to serve in a
manner similar to an attestation nonce.  If used, the trust
orchestrator is responsible for negotiating a random base nonce with a
verifying party at the time of initialization of a modeling namespace
and providing it to the TMA.

The TMA uses the base nonce to extend each security event state point
that is generated by the model.  This causes the state and measurement
values of the model to become dependent on this base nonce, a process
that can be used to defeat a replay attack against the security model.

Control plane
-------------

Both primary functions of TSEM: security modeling domain management
and the internal TMA implementation, are controlled by the tsemfs
pseudo-filesystem, that uses the following mount point:

/sys/fs/tsem

The following file documents, in detail, the interfaces provided by
the filesystem:

Documentation/ABI/testing/tsemfs

This filesystem is primarily intended for use by trust orchestrators
and must be mounted in order for orchestrators to create and manage
security modeling domains.

The following files grouped below by generic functionality, are
presented in the filesystem:

	control

	id
	aggregate

	measurement
	state
	points
	trajectory
	forensics

The /sys/fs/tsem directory contains the following sub-directory:

	ExternalTMA

That is used to hold files that will be used to export security event
descriptions for externally modeled domains.

The files are process context sensitive.  Writing to the control file
or reading from the informational files, will act on or reference the
security domain that the access process is assigned to.

The TSEM implementation at large is controlled by the only writable
file, which is the 'control' file.

The following keywords are used by trust orchestrators to create
internally or externally modeled security domains for the writing
process:

	internal
	external

The following keywords are used by trust orchestrators to set the
trust status of a process after processing of a security event by an
external TMA:

	trusted PID
	untrusted PID

	Where PID is the process identifier that is provided to the
	TMA in the security event description

By default a modeling domain runs in free modeling mode.  The modeling
mode is changed by writing the following keywords to the control file:

	seal
	enforce

The following keyword and argument are used to load a security model
into an internal modeling domain:

	state HEXID

	Where HEXID is the ASCII base 16 representation of a security
	state point that is represents a valid security event in the
	model.

	After writing a series of state values the trust orchestrator
	would write the 'seal' keyword to the control file to complete
	creation of a security model.  Writing the 'enforce' keyword
	to the control file will result in that model being enforced.

The following keyword and argument is used to set a base nonce for the
internal TMA:

	base HEXID

	Where HEXID is the ASCII base 16 representation of a value
	that each measurement is to be extended with before being
	committed as a measurement value for the model.

The following keyword and argument is used to create a file digest
pseudonym for the internal TMA:

	pseudonym HEXID

	Where HEXID is the ASCII base 16 representation of a file
	digest pseudonym that is to be maintained by the model.  See
	the ABI documentation for how the argument to this verb is
	generated.

The 'id' file is used to determine the modeling domain that the
process is running in.  The domain id value of 0 is reserved for the
root modeling domain, a non-zero value indicates that the process is
running in a subordinate modeling domain.

The 'aggregate' file is used by trust orchestrators for internally
modeled domains to obtain the hardware measurement value.  A trust
orchestrator for an internally modeled domain needs this value in
order to generate a platform specific security model for subsequent
enforcement.  A trust orchestrator for an externally modeled domain
can capture this value since it is exported, through the trust
orchestrator, to the TMA.

The remaining five files: measurement, state, points, trajectory and
forensics, are used to export the security model characteristics of
internally modeled domains.

The 'measurement' file outputs the classic measurement value of the
modeling domain that the calling process is running in.  This value is
the linear extension sum of the security state points in the model.

The 'state' file outputs the security state measurement value as
described in the 'Security model functional definitions' section of
this document.

The 'points' file outputs the set of security state points in the
model.  These points represent both valid and invalid state points
generated by the security model implemented for the domain.

The 'trajectory' file outputs the description of each security event
recorded by the model in time dependent form.

The 'forensics' file outputs the description of security events that
have occurred when the domain security model is running in a sealed
state.

The ABI documentation file contains a complete description of the
output that is generated by each of these files.

A security model for an internally modeled domain is loaded by
writing the valid security points to the 'state' file in the control
plane.  This will result in the 'trajectory' file having no event
descriptions for a sealed model, since the event description vector is
only populated when a new state point is added to the model.

Since the state points are generated with a cryptographic hash
function, the first pre-image resistance characteristics of the
function prevents a security model description from disclosing
information about the characteristics of the workload.

Trust orchestrators
===================

In security modeling, the need for a trust orchestrator system is
embodied in Heisenberg's reflections on quantum mechanical modeling.
A modeled system cannot model itself without affecting the functional
value of the security model being implemented.  An external entity is
needed to setup, configure and monitor the state of a modeled system,
in a manner that does affect the state of the modeled system itself.

After creating and configuring a modeling domain, the orchestrator is
responsible for executing and monitoring a process that is run in the
context of the domain.  The trust orchestrator is also responsible for
providing access to the security model implemented by the TMA.

Trust orchestrators for externally modeled domains, have an
associated TMA that is responsible for implementing the security model
for a domain.  The TMA represents the the root of trust for the
modeled domain.  The TMA advises the trust orchestrator as to what the
new trust status for a process should be set to, based on the modeling
of the security event that is presented to it by the trust
orchestrator.

In a trust orchestration architecture, secondary to their integral
role in maintaining the trust state of the system, the trust
orchestrators are the highest value security asset running on the
system.  In order to support this the Linux TSEM implementation
implements a new security capability, CAP_TRUST, that only the trust
orchestrators are designed to run with.

The CAP_TRUST capability is defined as a capability that allows the
ability of it's holder to modify the trust state of the system.  The
ability to create the proposed IMA namespaces would also be a
candidate for this capability.

Trust orchestrators are designed to drop the CAP_TRUST capability
before forking the process that will be responsible for launching a
modeled workload.  This provides an architecture where the root of
trust for the system can be predicated on a small body of well audited
orchestration utilities, that can be linked to a hardware root of
trust implemented by a TPM or hardware based TMA.

Quixote
=======

	"He is awkward, past his prime and engaged in a task beyond his
	 capacities."
				- Don Quixote's able mount Rocinante

The Quixote Trust Orchestration System, released in concert with TSEM,
is an initial implementation of a system that embodies the
characteristics described above.  While currently under development by
a small team, it provides all off the basic functionality needed to
demonstrate, and use, TSEM based security modeling.

It is anticipated that Quixote would not be the only such system to
take advantage of TSEM.  Given the burgeoning capability set of
systemd, it would be an architecturally valid concept to have systemd,
or other system init equivalents, gain the ability to launch critical
system services in modeled environments.

The source code for Quixote, and patches to the LTS kernels back to
5.4, are available at the following URL:

ftp://ftp.enjellic.com/pub/Quixote

The build of Quixote is somewhat formidable, given that it spans the
range from system programming though SGX programming and into embedded
micro-controller systems.  In order to facilitate experimentation,
binaries pre-compiled against MUSL libc are provided that have
virtually no system dependencies, other than a TSEM enabled kernel.

Sample utilities
----------------

The Quixote TSEM implementation implements a separate trust
orchestration utility for each TMA environment, nee Sancho partner,
that is supported:

quixote	     -> TMA run in the kernel for internally modeled domains.

quixote-us   -> TMA run in a userspace process.

quixote-xen  -> TMA run in a Xen based stub domain.

quixote-sgx  -> TMA run in an SGX enclave.

quixote-mcu* -> TMA run in a micro-controller implementation.

* = See discussion below.

Each utility runs in one of two modes: process or container

In process mode, a shell process is run as the workload process in
modeling domain.  This mode is selected with the -P command-line
option.

In container mode, the default, the OCI runc utility is run as the
workload process, with a 'bundle' argument that specifies a directory
that contains a JSON container definition for a directory hierarchy in
the bundle directory.  The /var/lib/Quixote/Magazine directory
contains the bundle directories.

The -c command-line option selects container mode, the argument to the
option specifies the bundle directory for the runc utility.

In order to support the creation of security models, each utility
supports the -o command-line option to specify that a security model
description be output when the modeled workload terminates.  The model
is written name of the file supplied via the command-line option.

If the -t command-line option is also specified, the security
execution trajectory, rather than a model definition, is written to
the output file.  This trajectory represents the description of the
security events that were modeled.  This trajectory can be converted
to security state points with the generate-states utility that is also
provided in the utilities package.

The -m command-line option is used to specify a model that is to be
loaded into the TMA and optionally enforced.  By default the security
model output with the -o command-line option will place the TMA in a
sealed modeling state.  Any security events that are non-compliant
with the model will be registered as forensics events.

Adding the -e command-line option, with the -m option, will cause the
loaded model to be enforced.  Any forensic events will cause a
permission denial to be returned to the caller of the LSM hook.

The Quixote package also includes a utility, quixote-console, for
interrogating the model state of a TMA.  The following command-line
options request output of the following characteristics of the model:

-E -> The log of denied events.

-F -> The current forensics execution trajectory.

-M -> The current security model description.

-P -> The current security state points.

-S -> The state value of the model.

-T -> The current security execution trajectory.

Executing the utility, without these arguments, will cause a
command-line version of the utility to be presented that takes the
following arguments:

show trajectory

show forensics

show points

show state

show model

quit

It is important to note that any of the values output represent the
current state of the model and do not reflect a cumulative model of
the workload.  Capturing a complete workload model requires the use of
the -m command-line argument to the trust orchestrators to capture a
model that is representative of the entire execution trajectory of the
workload.

For informative purposes the following security model definition
represents the execution and simple termination of a shell session run
on a system with a hardware TPM:

aggregate de2b9c37eb1ceefa4bcbc6d8412920693d3272f30eb5ba98d51d2f898d620289
state 97b29769580b412fbf55e326a98d6a1b97c6ebf446aaf78ea38c884e954ca5b2
state 7c435854b4fa421175ec0a5d3ca7c156480913d85c03155ea3305afa56c9717d
state 554d9f62693d522c9a43acf40780065f99cea3d67ca629ac4eaab4e22d4e63c2
state 1b228046c4c2e7aa14db9a29fcff6f718f4f852afbfb76c8a45af7bf0485f9ce
state 24fd04b10e2b5016e0061952f3bdea959e0fa80a55ff0f4e8e13f9f72ede7498
state da6038511db71b08c49a838d178ed055e0b7bfc42548b4c2d71eca046e9a222e
state 94b24ad4c8902f8ecb578a702408e8458e72c0774c402c3bd09ec5f390c4d0ae
state 5ffa5a2a38f42d89ae74a6d58be8b687c1baed9746d9c6a7ae3c632a2e7c082f
state a2e309d84bd4a52466c22779a622254c65ad1208583d70113751c4624baa7804
state e93ceb0b1bf3cd58373a9e9ab4aca11a507782bbfde395ff68f8bfaf1678ed43
state bf42388d63887368605fac9816134bc67314762c3a97b440cc48c5a30c07fdb9
state eaa342599d682d63be4b64e159b98f21d85f0133ef5b28588e444ad12e446bf6
state 2b9c86bc34202504c398c2f177d1dcf807b2f267c160bf8ebda863a9b427917f
state 686fc3c958f2e4f2ce3b2c6a2cb3fff44ccc4db98869bd377b14e557a5191231
state 613c39fd2a58413b32f448c13ea4d6bc38b77966dfc5560e39e4b37d2b2f5675
state 70e276bfd7c20262cd9c9f5b09a922f11d16d1e3a602e8005d68e9ed6afc9b5d
state 456aaedc5c1fc63f852ee97ae9561aba2a06c416154ecb9d7a1bf9d9a8c9c064
state 97507c4c91af4a9b34b4d66118f6cc0ba1f8b55b8bb6e623dcafe27b100aea07
state ea635c48031f81140b3561ed2291a3b1790a302e6adf5244320593b08a5af924
state 2fd6a4d6ea1869a193926e998fbdf855916b510257d379762f48a1df63a810d4
state 9c4cb7ef4848be1e29f9eb35fadaf5bfdc1fa3cbb22b6407cbd31b7088257026
state 66640cbf9ae772515070f8613182b6852bf46220df0833fbe6b330a418fad95b
state 6b0d1890cbd78c627e23d7a564e77a5ee88fb20e0662ce5e66f3727ebf75fa1d
state bd28fa43b34850591fdf6fb2aa5542f33c21c20ee91b4bc2034e199b4e09edc1
state 04425354419e53e6e73cde7d61856ff27763c2be01934e9990c1ae9f8d2a0b6e
state 2650d86382f6404367b7fdeec07f873b67b9ce26caef09d035b4dff09fce04d5
state df2f91f5fd84ca4621092420eaf1b0a3743b328a95e3f9e0b7b1281468462aa2
state c730c66ecfabe99480e61a7f25962582ca7bb6f2b17983048e77adde1fe7f72b
state 0fc937b71d0067fcc2c2f37c060763de250b3142e621174ffedc1b2520cdf6fd
state 7f267400a3ccf462c77ae5129799558c2c62d8bc5b388882caec813ab4cf7b7f
seal
end

As was previously discussed, the model should be cryptographically
secure against the elucidation of the security events that resulted in
the described security states.

The Quixote package also contains utilities for generating signed
versions of these security models.  In what is a nod to the politics
of trusted systems, the Quixote TMA implementations support
self-signed security models.

* MCU TMA's
-----------

One of the objectives of TSEM/Quixote is to explore architectures for
trusted systems that extend beyond what is provided by the TPM model
for security co-processors.  The MCU based reference implementations
allow experimentation with hardware based TMA's.

The Quixote TSEM utilities include TMA implementations for the
following following ARM32 based micro-controller platforms:

STM32L496

STM32L562

NRF52840-DK

NRF52840-DONGLE

The STM32L496 platform, in addition to the base TMA implementation,
includes support for a CAT1-M based cellular modem.  This demonstrates
the ability of an external TMA to conduct remote, out-of-band,
signaling of security violations for modeled platforms/workloads.

The STM32L562 platform is a low power MCU designed for security
focused IOT implementations.  It includes hardware hashing, hardware
asymmetric encryption and Trust Zone support.

Of primary interest is the NRF52840-DONGLE implementation.  This is a
'USB fob' form factor board that GOOGLE uses as the basis for its
OpenSK security key implementation.  This form factor allows the
development and experimentation with deployable hardware based TMA
implementations.

The NRF52840-DONGLE architecture was also chosen by the NLnet
sponsored 'FobNail' project, that is developing a hardware based
attestation server:

https://fobnail.3mdeb.com/

The Fobnail projects discusses the notion of their architecture
expanding to provide protection for a Linux system at large.
Quixote/TSEM running, on the NRF52840-DONGLE micro-controller, is a
demonstration of such an implementation.

===============
Closing Remarks
===============

	"Sometimes it is the people no one can imagine anything of who
	 do the things no one can imagine.
				- Alan Turing

While this document is of some length and detail, it hopefully
fulfills its obligation to provide sufficient prose for the
justification of the security model that TSEM addresses, and in
combination with trust orchestrators, implements.

The MAINTAINERS file has contact information for feedback, patches
and/or questions regarding TSEM and its reference TOS implementation.

     The Quixote Team - Flailing at the Travails of Cybersecurity

	With all due respect to Miguel de Cervantes Saavedra.

   From the glacial moraine lake country of West-Central Minnesota.
