.. SPDX-License-Identifier: MIT
.. Copyright (C) 2026 Szymon Wilczek

=========================
Including header comments
=========================

The public C API is described once, in the comments of the headers under
``include/``. A page includes those comments with the ``kernel-doc``
directive. The directive is :ghsrc:`Documentation/sphinx/kerneldoc.py`.

The directive
=============

.. code-block:: rst

   .. kernel-doc:: include/lota_gaming.h

   .. kernel-doc:: include/lota_gaming.h
      :identifiers: lota_connect lota_disconnect

   .. kernel-doc:: include/lota_gaming.h
      :doc: Connection lifetime

The argument is a path relative to the repository root.

``:identifiers:``
  The functions, macros, structs, unions, enums and typedefs to render, in
  that order. Without it every comment in the file is rendered, except
  ``DOC:`` sections.

``:doc:``
  Render the ``DOC:`` section with that title.

Each declaration becomes an entry in the Sphinx C domain (``c:function``,
``c:struct`` and so on), so ``:c:func:`lota_connect``` links to it from any
page.

The comment format
==================

A comment opens with ``/**`` on a line of its own and documents the
declaration that follows it:

.. code-block:: c

   /**
    * lota_connect_opts() - lota_connect() with custom options.
    * @opts: socket path, timeout and publisher; NULL for the defaults.
    *
    * Return: as for lota_connect().
    */
   struct lota_client *lota_connect_opts(const struct lota_connect_opts *opts);

The first line is the name and a one-line summary separated by ``-``:

* ``name() - ...`` for a function,
* ``struct name - ...``, ``union name - ...``, ``enum name - ...``,
  ``typedef name - ...`` for a type,
* ``name - ...`` for a macro or a variable,
* ``DOC: Title`` for a section of free text with no declaration.

``@name:`` lines follow, one per parameter or struct member; a description
continues on the next lines until a blank line. The body after the blank
line is free text. ``Return:``, ``Context:``, ``Note:``, ``Example:`` and
``Locking:`` start a titled section.

Inside the text ``@name`` renders as a literal, ``%NAME`` as a literal
constant, ``name()`` as a link to that function and ``&struct name`` as a
link to that type.

Warnings
========

Each of these is a warning, and ``make check-docs-strict`` fails on any
warning:

* a ``/**`` comment whose first line does not parse,
* a parameter or member in the declaration with no ``@name:`` line,
* an ``@name:`` line for a parameter or member the declaration lacks,
* an ``:identifiers:`` name or a ``:doc:`` title with no comment,
* a path that does not exist.

Macros a header puts before a prototype, such as ``LOTA_HOOK_EXPORT``, are
listed in ``c_id_attributes`` in ``Documentation/conf.py``; a new one goes
there too, or the C domain cannot parse the prototype.

:ghsrc:`tests/integration/test_kerneldoc_warnings.sh` renders every comment
under ``include/`` and expects a clean build, then feeds the directive one
broken header per warning and expects each to fail. ``make check-docs-strict``
and the documentation CI job run it, so a broken comment fails even before a
page includes it.
