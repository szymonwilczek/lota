.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

==========================
LOTA SELinux policy module
==========================

The ``lota`` policy module confines the agent in the ``lota_agent_t`` domain,
labels its files, and declares the types of the TPM device and of the ports
the agent attests to. ``lota.te`` holds the rules, ``lota.fc`` the file
contexts and ``lota.if`` the interfaces other modules call. The sources are
GPL-2.0-only.

The packages ship the compiled ``lota.pp`` and ``lota.if`` in
``/usr/share/lota/selinux``, and ``lota-install`` loads the module in its
SELinux stage (`lota-install.rst
<../Documentation/admin-guide/lota-install.rst>`_). This directory builds
and loads the module by hand.

Building and loading
====================

The build needs ``selinux-policy-devel``, and the targets below also need
``semodule`` and ``restorecon`` from ``policycoreutils``:

.. code-block:: console

   # dnf install selinux-policy-devel policycoreutils \
       policycoreutils-python-utils
   $ make
   # make install
   # make verify

Build ``lota.pp`` against the ``selinux-policy-devel`` of the host that loads
it. ``pidfs_t`` is referenced in an ``optional_policy`` block, which is
dropped where the base policy does not define the type; the rest of the
module loads.

Targets
-------

``all``
  The default. Builds ``lota.pp`` with the devel Makefile.

``install``
  Needs root. Builds, loads ``lota.pp`` with ``semodule -i``, and copies it to
  ``/usr/share/selinux/packages``. Copies ``lota.if`` to
  ``/usr/share/selinux/devel/include/contrib`` when
  ``/usr/share/selinux/devel/include`` exists, and otherwise prints that it
  did not. Labels ``LOTA_PORT`` (below). Creates ``/etc/lota/policies``,
  ``/etc/lota/ca``, ``/var/lib/lota/aik``, ``/var/lib/lota/baseline``,
  ``/run/lota`` and ``/usr/lib/lota``, runs ``restorecon -Rv`` on each path of
  ``LOTA_PATHS`` that exists, and prints the value of each boolean.
  ``LOTA_PATHS`` lists ``/usr/bin/lota-agent``, ``/usr/sbin/lota-agent``,
  ``/usr/lib/lota``, ``/usr/lib64/lota``, ``/etc/lota``, ``/var/lib/lota`` and
  ``/run/lota``; ``/usr/local/bin/lota-agent`` and ``/var/run/lota`` from
  ``lota.fc`` are not relabelled.

``uninstall``
  Needs root. Deletes every local port record of type ``lota_port_t``,
  removes the module and the two files ``install`` copied. The port records
  go first: a record that names a type the policy no longer has comes back
  into force when the module is loaded again.

``reload``
  ``uninstall``, then ``install``. Only ``LOTA_PORT`` is labelled again; the
  other port records are gone.

``check``
  Builds ``lota.pp`` and prints the last 20 lines of the build output when
  it fails.

``verify``
  Reports whether ``semodule -l`` lists the ``lota`` module, whether
  ``semanage port -l`` lists ``lota_port_t``, and the value of each
  boolean.

``audit``
  AVC records of ``ausearch -ts recent`` that mention ``lota``, ``steam``,
  ``wine`` or ``games``.

``suggest``
  The same filter over ``ausearch -ts today``, passed to ``audit2allow -m
  lota_local``. It prints the module text and loads nothing.

``clean``
  Removes ``*.pp`` and ``tmp/``.

``LOTA_PORT``
  A port for ``install`` to label ``lota_port_t``; none by default.
  ``LOTA_PORT_PROTO`` is its protocol, ``tcp`` by default. A port that
  another type names on its own is reported and left alone, because a local
  record would take it from every domain on the host. A port inside a range
  of another type is labelled.

A package upgrade loads the new ``lota.pp`` when ``semodule -l`` lists
``lota``: the store holds a copy, and a replaced file does not change it.

Types and file contexts
=======================

.. list-table::
   :header-rows: 1

   * - Type
     - Labels
   * - ``lota_agent_t``
     - The agent process.
   * - ``lota_agent_exec_t``
     - ``/usr/bin/lota-agent``, ``/usr/sbin/lota-agent``,
       ``/usr/local/bin/lota-agent``.
   * - ``lota_bpf_t``
     - ``/usr/lib/lota`` and ``/usr/lib64/lota``, with their contents.
   * - ``lota_etc_t``
     - ``/etc/lota`` and its contents.
   * - ``lota_var_t``
     - ``/var/lib/lota``, ``/run/lota`` and ``/var/run/lota``, with their
       contents, the IPC socket ``/run/lota/lota.sock`` among them.
   * - ``lota_tpm_device_t``
     - ``/dev/tpm[0-9]*`` and ``/dev/tpmrm[0-9]*``, set by the udev rule
       (`TPM device label`_).
   * - ``lota_port_t``
     - Nothing until a port record names it (`Ports`_).

``restorecon`` applies the contexts; ``restorecon -R /etc/lota`` labels the
directory and every file below it. A file created later takes the type of the
directory it is created in, except ``lota-agent.pid``, which the agent creates
in the pid directory as ``lota_var_t``. ``lota-agent --add-publisher`` writes
``lota.conf`` to a new file and renames it over the old one; it copies the old
file's label onto the new one first, and prints a warning naming
``restorecon`` when it cannot.

Booleans
========

.. list-table::
   :header-rows: 1

   * - Boolean
     - Default
     - While on
   * - ``lota_network_attest``
     - on
     - ``lota_agent_t`` may connect to ``lota_port_t`` and ``http_port_t``
       ports.
   * - ``lota_bpf_load``
     - on
     - ``lota_agent_t`` may create, read and write BPF maps and load and
       run BPF programs.

``setsebool`` changes a boolean at once, and ``-P`` keeps the value across
reboots:

.. code-block:: console

   # setsebool -P lota_network_attest off
   # getsebool -a | grep lota

With the boolean off the domain still creates sockets and resolves names,
and connects to no ``lota_port_t`` or ``http_port_t`` port. That covers the
default verifier port 8443, which the base policy labels ``http_port_t``.

The agent domain
================

``lota_agent_t`` is entered from ``init_t`` when systemd starts
``lota-agent.service``. The unit sets ``NoNewPrivileges=yes``, which needs
the ``nnp_transition`` rule, and ``nosuid_transition`` covers a binary on a
``nosuid`` mount. ``lota-agent`` started from a login shell keeps the
shell's domain.

The domain holds:

* the capabilities ``dac_override``, ``dac_read_search``, ``sys_admin``,
  ``sys_ptrace``, ``chown``, ``kill``, ``bpf`` and ``perfmon``, with
  ``audit_write`` from ``logging_send_audit_msgs``, and ``kill`` and
  ``sys_ptrace`` in a user namespace, where a title under Proton is checked;
* read and write on ``lota_tpm_device_t`` and on the stock
  ``tpm_device_t``, which a node carries until udev relabels it;
* read on every file type except ``security_file_type`` and
  ``system_map_t``, for runtime image measurement. A mapping of such a file
  stays unmeasured (`runtime-measurement.rst
  <../Documentation/agent/runtime-measurement.rst>`_);
* ``signal`` and ``sigkill`` on every domain, for ending a protected
  process (`protection.rst <../Documentation/agent/protection.rst>`_);
* manage on ``lota_var_t``, read on ``lota_etc_t``, read, execute and map
  on ``lota_bpf_t``;
* create, bind and watch under ``user_tmp_t``, for the container socket
  ``/run/user/<uid>/lota/lota.sock`` (`ipc.rst
  <../Documentation/agent/ipc.rst>`_). Without these the socket does not
  appear;
* ``acquire_svc`` on the system bus, for ``org.lota.Agent1``.

The domain has no access to ``/run/systemd/userdb``. The unit sets
``SYSTEMD_BYPASS_USERDB=1``, so a group lookup reads ``/etc/group``, where
the packages create ``lota``; a group defined only in userdb does not
resolve in the service.

TPM device label
================

``configs/udev/99-lota-tpm.rules`` sets ``/dev/tpm[0-9]*`` and
``/dev/tpmrm[0-9]*`` to ``root:root``, mode 0600, and labels them
``lota_tpm_device_t``. The packages install it in
``/usr/lib/udev/rules.d``.

The label takes the TPM from confined domains that the base policy grants
``tpm_device_t``. It does not take it from unconfined domains: the base
policy gives the attribute ``devices_unconfined_type`` every device node,
with ``relabelfrom`` and ``relabelto``, and ``unconfined_t``, the domain of a
root login, has the attribute. A loaded module cannot revoke a base policy
grant. The label binds only with SELinux enforcing; otherwise the 0600 mode
alone applies. PCR 14 extends that reach the TPM anyway are what the boot
commitment records (`lifecycle.rst
<../Documentation/agent/lifecycle.rst>`_).

At startup the agent reads ``security.selinux`` on ``/dev/tpmrm0`` and
``/dev/tpm0`` and refuses to start when a node present lacks
``lota_tpm_device_t``::

   TPM device /dev/tpmrm0 carries SELinux label
   system_u:object_r:tpm_device_t:s0; expected lota_tpm_device_t (udev rule
   configs/udev/99-lota-tpm.rules did not relabel the device, so any other
   root domain can rw the TPM and DoS LOTA attestation availability)

The unit does not restart on this refusal. A file system that does not support
extended attributes (``ENOTSUP``) passes the check. So does ``ENODATA``, which
the read returns when no SELinux policy is loaded; the agent logs a warning
that the label was not checked. Any other error reading the attribute refuses
the start the same way. With neither node present the agent logs a warning and
goes on.
``--insecure-allow-mutable-rootfs`` turns the refusal into a warning.

udev applies ``SECLABEL`` when it adds a device, and ``/dev/tpmrm0`` is in
subsystem ``tpmrm``. After a manual install of the rule:

.. code-block:: console

   # udevadm control --reload-rules
   # udevadm trigger --action=add --subsystem-match=tpm --subsystem-match=tpmrm
   # ls -Z /dev/tpm0 /dev/tpmrm0
   # systemctl start lota-agent

A ``trigger`` without ``--action=add`` sends ``change``, leaves the label as
it was and exits 0. A reboot adds both nodes again.

``lsof /dev/tpmrm0 /dev/tpm0`` lists the processes that hold the TPM open.
A TPM in dictionary-attack lockout is in `tpm.rst
<../Documentation/agent/tpm.rst>`_.

Ports
=====

The module labels no port: a loadable module cannot carry ``portcon``.
``lota-install`` labels the CA and verifier ports it is given that carry
neither ``lota_port_t`` nor ``http_port_t`` and that no other type names on
its own. Any other port the agent attests to needs a record:

.. code-block:: console

   # semanage port -a -t lota_port_t -p tcp 8573

On an enforcing host a connect refused with ``EACCES`` is logged with the
cause the agent reads from ``/sys/fs/selinux``. With ``lota_network_attest``
on, an example::

   Cannot reach 192.0.2.10:8573. SELinux is enforcing and TCP port 8573
   carries no LOTA label, which is what refuses this connect. Label the port
   and the next round goes through:
     sudo semanage port -a -t lota_port_t -p tcp 8573

With the boolean off, the line says ``the lota_network_attest boolean is
off`` and gives ``sudo setsebool -P lota_network_attest on``; a port record
changes nothing then. Without the module there is no boolean to read, and
the line gives both commands. On a permissive host, or one without SELinux,
it adds nothing to the error.

The AVC of such a refusal is a ``name_connect`` on the port's type.

Interfaces
==========

Another module calls these from ``lota.if``. The policy development
Makefile reads the ``.if`` files of every directory under
``/usr/share/selinux/devel/include``; ``make install`` puts it in
``contrib``. The packages put it in ``/usr/share/lota/selinux``, so a host
that builds policy from them copies it once:

.. code-block:: console

   # install -m 0644 /usr/share/lota/selinux/lota.if \
       /usr/share/selinux/devel/include/contrib/lota.if

Without it ``checkmodule`` stops at the interface name as an unknown token.

.. list-table::
   :header-rows: 1

   * - Interface
     - Grants the domain
   * - ``lota_query_status(domain)``
     - Search on ``lota_var_t`` directories, write on its sockets,
       ``connectto`` on ``lota_agent_t``, read on its files: the socket
       ``/run/lota/lota.sock``.
   * - ``lota_query_status_container(domain)``
     - Search on ``/run`` and on ``user_tmp_t`` directories, write on
       ``user_tmp_t`` sockets, ``connectto`` on ``lota_agent_t``: the socket
       ``/run/user/<uid>/lota/lota.sock``.
   * - ``lota_verify_integrity(domain)``
     - Search on ``/var/lib`` and on ``lota_var_t`` directories, read on its
       files.
   * - ``lota_gaming_client(domain)``
     - The three above.
   * - ``lota_request_attest(domain)``
     - ``lota_query_status`` and ``signal`` on ``lota_agent_t``. No signal
       makes the agent attest.
   * - ``lota_read_config(domain)``
     - Read on ``lota_etc_t``.
   * - ``lota_anticheat_client(domain)``
     - ``lota_gaming_client``, ``lota_request_attest`` and
       ``lota_read_config``.
   * - ``lota_domtrans(domain)``
     - Execute ``lota_agent_exec_t`` with a transition to ``lota_agent_t``.
   * - ``lota_exec(domain)``
     - Execute ``lota_agent_exec_t`` with no transition.
   * - ``lota_role_types(role)``
     - ``lota_agent_t`` for the role.
   * - ``lota_admin(domain, role)``
     - ``ptrace`` and every signal on ``lota_agent_t``, its process state,
       ``lota_domtrans``, ``lota_agent_t`` for the role, and manage and
       relabel on ``lota_etc_t``, ``lota_var_t`` and ``lota_bpf_t``.
   * - ``corenet_tcp_connect_lota_port(domain)``
     - ``name_connect`` on ``lota_port_t``.
   * - ``corenet_tcp_bind_lota_port(domain)``
     - ``name_bind`` on ``lota_port_t``.

A title runs in the domain of the user who starts it, ``unconfined_t`` on a
default desktop, which needs none of these. A confined title calls
``lota_gaming_client``:

.. code-block:: none

   lota_gaming_client(mygame_t)

Denials
=======

.. code-block:: console

   # ausearch -m avc -ts recent | grep lota
   # sesearch -A -s lota_agent_t -t user_tmp_t -ds -dt
   # ps -eZ | grep lota-agent

To log denials of the agent without enforcing them, make its domain
permissive and start the service again; ``-d`` ends it:

.. code-block:: console

   # semanage permissive -a lota_agent_t
   # semanage permissive -d lota_agent_t

A restart of the agent within one boot is visible in its status (`lifecycle.rst
<../Documentation/agent/lifecycle.rst>`_).
