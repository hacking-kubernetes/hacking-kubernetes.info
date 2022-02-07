# Free Download

ControlPlane is sponsoring the first four chapters of the book, [download them for free](https://control-plane.io/hackingkubernetes/).

# Hacking Kubernetes

Running cloud native workloads on Kubernetes can be challenging: keeping them secure is even more so. Kubernetes' complexity offers malicious in-house users and external attackers alike a large assortment of attack vectors. In this book,
[Andrew Martin](https://twitter.com/sublimino) and [Michael Hausenblas](https://twitter.com/mhausenblas) review Kubernetes defaults and threat models and shows how to protect against attacks.

The book is published and available via [O'Reilly](https://learning.oreilly.com/library/view/hacking-kubernetes/9781492081722/) or [Amazon](https://www.amazon.com/Hacking-Kubernetes-Threat-Driven-Analysis-Defense/dp/1492081736).

![book cover](hk-cover.png)

## Coverage

* Chapter 1: we set the scene, introducing our main antagonist and also what threat modelling is.
* Chapter 2: where we focuses on pods, from configurations to attacks to defenses.
* Chapter 3: we switch gears and dive deep into sandboxing and isolation techniques (KVM, gVisor, Firecracker, Kata).
* Chapter 4: covers supply chain attacks and what you can do to detect and mitigate them.
* Chapter 5: where we review networking defaults and how to secure your cluster and workload traffic incl. service meshes and eBPF.
* Chapter 6: we shift our focus on the persistency aspects, looking at filesystems, volumes, and sensitive information at rest.
* Chapter 7: covers the topic of running workloads for multi-tenants in a cluster and what can go wrong with this.
* Chapter 8: we review different kinds of policies in use, discuss access control—specifically RBAC—and generic policy solutions such as OPA.
* Chapter 9: we cover the question what you can do if, despite controls put in place, someone manages to break  (intrusion detection system, etc.).
* Chapter 10: a somewhat special one, in that it doesn’t focus on tooling but on the human aspects, in the context of public cloud as well as on-prem environments.

## About the authors

Based on our combined 10+ years of hands-on experience designing, running, attacking, and defending Kubernetes-based workloads and clusters, we want to equip you, the cloud native security practitioner, with what you need to be successful in your job.

We both have served in different companies and roles, gave training sessions, and published material from tooling to blog posts as well as have shared lessons learned on the topic in various public speaking engagements. Much of what motivates us here and the examples we use are rooted in experiences we made in our day-to-day jobs and/or saw at customers.

# Notable CVEs

> Unless noted, these CVEs are patched, and are here to serve only as a historical reference. See also [@rasene's HackMD](https://hackmd.io/@raesene/r1KPVd0At).

- CVE-2017-1002101 - Subpath volume mount mishander. Containers using
subpath volume mounts with any volume type (including nonprivileged pods
subject to file permissions) can access files/directories outside of the
volume including the host’s filesystem.

- CVE-2017-1002102 - Downward API host filesystem delete. Containers using
a Secret, ConfigMap, projected or downwardAPI volume can trigger
deletion of arbitrary files/directories from the nodes where they are
running.

- CVE-2017-5638 - (Non-Kubernetes) Apache Struts invalid `Content-Type`
header parsing failure, allowing arbitrary code execution. The bug in
the Jakarta Multipart parser registered the input as OGNL code,
converted it to an executable, and moved it to the server’s temporary
 directory.

- CVE-2018-1002105 - API server websocket TLS tunnel
error mishandling. Incorrect error response handling of proxied upgrade
requests in the `kube-apiserver` allowed specially crafted requests to
establish a connection through the Kubernetes API server to backend
servers. Subsequent arbitrary requests over the same connection transit
directly to the backend authenticated with the Kubernetes API server’s
TLS credentials.

- [CVE-2019-16884](https://oreil.ly/4It2O) - `runc` hostile image AppArmor
bypass. Allows AppArmor restriction bypass because
`libcontainer/rootfs_linux.go` incorrectly checks mount targets, and
thus a malicious Docker image can mount over a `/proc` directory.

- [CVE-2019-5736](https://oreil.ly/4aaXw) - `runc` _/proc/self/exe_. `runc`
allows attackers to overwrite the host `runc` binary (and consequently
obtain host root access) by leveraging the ability to execute a command
as root within one of these types of containers: (1) a new container
with an attacker-controlled image, or (2) an existing container, to
which the attacker previously had write access, that can be attached
with docker exec. This occurs because of file-descriptor mishandling,
related to _/proc/self/exe_.

- [CVE-2019-11249](https://oreil.ly/79ROq) - `kubectl cp` `scp` reverse
write. To copy files from a container Kubernetes runs `tar` inside the
container to create a Tar archive, and copies it over the network where
`kubectl` unpacks it on the user’s machine. If the `tar` binary in the
container is malicious, it could run any code and output unexpected
malicious results. An attacker could use this to write files to any path
on the user’s machine when `kubectl cp` is called, limited only by the
system permissions of the local user.

- CVE-2018-18264 - Kubernetes Dashboard before v1.10.1 allows attackers to bypass
authentication and use Dashboard’s ServiceAccount for reading Secrets
within the cluster.

- CVE-2019-1002100 - API Server JSON patch Denial of Service. Users that
are authorized to make HTTP `PATCH` requests to the Kubernetes API
Server can send a specially crafted patch of type ``json-patch'' (e.g.,
`kubectl patch --type json` or
`"Content-Type: application/json-patch+json"`) that consumes excessive
resources while processing.

- [CVE-2018-1002100](https://oreil.ly/bN0Fh) - Original `kubectl cp`. The
`kubectl` cp command insecurely handles `tar` data returned from the
container and can be caused to overwrite arbitrary local files.

- CVE-2019-1002101 - Similar to `CVE-2019-11249`, but extended in that the
`untar` function can both create and follow symbolic links.

- CVE-2019-11245 - `mustRunAsNonRoot: true` bypass. Containers for pods
that do not specify an explicit `runAsUser` attempt to run as uid 0
(root) on container restart, or if the image was previously pulled to
the node

- CVE-2019-11247 - Cluster RBAC mishandler. The Kubernetes
`kube-apiserver` mistakenly allows access to a cluster-scoped custom
resource if the request is made as if the resource were namespaced.
Authorizations for the resource accessed in this manner are enforced
using roles and role bindings within the namespace meaning that a user
with access only to a resource in one namespace could create, view,
update, or delete the cluster-scoped resource (according to their
namespace role privileges).

- CVE-2019-11248 - `kubelet` _/debug/pprof_ information disclosure and
denial of service. The debugging endpoint _/debug/pprof_ is exposed over
the unauthenticated `kubelet` `healthz healthcheck endpoint` port, which
can potentially leak sensitive information such as internal Kubelet
memory addresses and configuration or for limited denial of service.

- CVE-2019-11250 - Side channel information disclosure. The Kubernetes
`client-go` library logs request headers at verbosity levels of 7 or
higher. This can disclose credentials to unauthorized users via logs or
command output. Kubernetes components (such as `kube-apiserver`) which
make use of basic or bearer token authentication and run at high
verbosity levels are affected.

- [CVE-2020-8558](https://oreil.ly/9tLAP) - `kube-proxy` unexpectedly makes
localhost-bound host services available on the network.

- CVE-2020-14386 - Integer overflow from raw packet on the ``loopback''
(or localhost) network interface. Removing this with
`sysctl -w kernel.unprivileged_userns_clone=0` or denying `CAP_NET_RAW`
protects unpatched kernels from exploitation.

- CVE-2021-22555 - Linux Netfilter local privilege escalation flaw. When
processing `setsockopt IPT_SO_SET_REPLACE` (or `IP6T_SO_SET_REPLACE`) a
local user may exploit memory corruption to gain privileges or cause a
DoS via a user namespace. A kernel compiled with `CONFIG_USER_NS` and
`CONFIG_NET_NS` allows an unprivileged user to elevate privileges.

- [CVE-2021-25740](https://oreil.ly/srPzW) (unpatched) - Endpoint and
EndpointSlice permissions allow cross-Namespace forwarding. users to
send network traffic to locations they would otherwise not have access
to via a confused deputy attack.

- CVE-2021-31440 - Incorrect bounds calculation in the Linux kernel eBPF
verifier. By bypassing the verifier, this can exploit out-of-bounds
kernel access to escape, and the original proof of concept set UID and
GID to 0 and gained `CAP_SYS_MODULE` to load an arbitrary kernel outside
the container.

- [CVE-2021-25741](https://oreil.ly/irhM8) - Symlink exchange can allow host
filesystem access. A user may be able to create a container with subpath
volume mounts to access files and directories outside of the volume,
including on the host filesystem.

