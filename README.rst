vaultkeeper
============

.. image:: https://img.shields.io/travis/praekeltfoundation/vaultkeeper/develop.svg?style=flat-square
    :target: https://travis-ci.org/praekeltfoundation/vaultkeeper

.. image:: https://img.shields.io/codecov/c/github/praekeltfoundation/vaultkeeper/develop.svg?style=flat-square
    :target: https://codecov.io/github/praekeltfoundation/vaultkeeper?branch=develop

| 
| A Secure Introduction agent for applications consuming secrets from HashiCorp's Vault, designed to work with `vault-gatekeeper-mesos <https://github.com/ChannelMeter/vault-gatekeeper-mesos>`_. See Jeff Mitchell's `Secure Introduction at Scale <https://www.youtube.com/watch?v=R-jJXm3QGLQ>`_ for more background information on this project's architecture.
|
| ``vaultkeeper`` couples the lifetime of your dynamically-generated secrets to that of your consumer applications, minimising the secrets' temporal attack surface. When used with Dockered applications, ``vaultkeeper``'s design ensures that your consumer app is only launched once its secrets are fetched and ready.
|
| ``vaultkeeper`` supports the ``SET_ROLE`` operation `necessary to revoke dynamically-generated PostgreSQL credentials <https://github.com/jdelic/django-postgresql-setrole>`_.

Status
-------------

``vaultkeeper`` is in PoC stage, and supports the following Vault secret backends:

- `PostgreSQL Databases Plugin <https://www.vaultproject.io/api/secret/databases/postgresql.html>`_
- `RabbitMQ <https://www.vaultproject.io/api/secret/rabbitmq/index.html>`_
- `AWS <https://www.vaultproject.io/api/secret/aws/index.html>`_

Prerequisites
-------------

| To use ``vaultkeeper`` successfully, you must have:

- A Vault instance configured and running.
- A ``vault-gatekeeper-mesos`` instance configured and running with your Vault instance and Mesos instance.
- An application that uses Vault credentials and is configured to consume ``vaultkeeper`` output, such as a Django app using `django-vaultkeeper-adaptor <https://github.com/praekeltfoundation/django-vaultkeeper-adaptor>`_.

Installing the Package
----------------------

| Clone this project and install the package from source with the following commands in the root directory of the repository:

| ``$ pip install -r requirements.txt``
|

| Install the package for development with the following commands:

| ``$ pip install -r requirements.txt``
| ``$ pip install -e .[test]``

Configuration
-------------

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

| ``VAULTKEEPER_CONFIG`` - A JSON string in ``vaultkeeper`` config format. See ``configs/example_agent_config.json``
| ``VAULT_SECRETS`` - A JSON string in ``vaultkeeper`` secrets format. See ``configs/example_consumer_config.json``.
| ``MESOS_TASK_ID`` - The Mesos task ID assigned to this task, which should be automatically populated by Mesos.
| ``MARATHON_APP_ID`` - The Marathon app ID assigned to this task, which should be automatically populated by Marathon.

vaultkeeper Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

``vaultkeeper`` consumes its arguments from a JSON environment variable:

.. code-block:: JSON

    {
        "entry_cmd": "sh /scripts/django-entrypoint.sh",
        "output_path": "",
        "refresh_interval": 30,
        "lease_increment": 40,
        "renewal_grace": 15
    }

| ``entry_cmd`` - The entrypoint for the application to be managed by ``vaultkeeper``. This can be an arbitrary shell command.
| ``output_path`` - ``vaultkeeper``'s output location for fetched credentials.
| ``refresh_interval`` - Interval (in seconds) after which to renew all leases.
| ``lease_increment`` - Increment (in seconds) by which to extend a lease if it is due for renewal.
| ``renewal_grace`` - Time (in seconds) before a lease's expiry under which to renew the lease.

secrets Configuration
~~~~~~~~~~~~~~~~~~~~~

| ``vaultkeeper`` reads in a specification for the secrets it should fetch from Vault in JSON.
|
| An example secret file containing PostgreSQL and RabbitMQ credentials is shown below:
|

.. code-block:: JSON

    [{
            "id": "default",
            "backend": "postgresql",
            "endpoint": "0.0.0.0:5432/mydb",
            "vault_path": "database/creds/psql-rw",
            "schema": "public",
            "policy": "psql-rw",
            "set_role": "app_owner",
        },
        {
            "id": "broker1",
            "backend": "rabbitmq",
            "endpoint": "0.0.0.0:5672/myvhost",
            "vault_path": "/rabbitmq/creds/ampq-worker",
            "vhost": "myvhost",
            "policy": "ampq-worker"
    }]

Common base parameters in the secrets configuration file:

| ``id`` - The logical identifier for this secret. Identifiers must be unique within each consumer instance.
| ``backend`` - The Vault secret backend of this secret.
| ``endpoint`` - The endpoint for the resource. This should be a socket address with the applicable namespace (ie. vhost, database name) appended.
| ``vault_path`` - The Vault path from which the secret should be read.
| ``policy`` - The resource policy, as designated on Vault, attached to this secret.

Deployment
----------

| ``vaultkeeper`` outputs secrets as JSON. Your application needs to be able to parse and consume this output. For Django applications, ``django-vaultkeeper-adaptor`` is recommended.
|
| Supply the ``vaultkeeper`` configuration file with the entrypoint for the application you wish to manage. Ensure that your consumer application knows where ``vaultkeeper``'s secret output will be stored.
|
| Thereafter, instead of running your application's conventional entrypoint script, run ``vaultkeeper`` instead:

| ``$ vaultkeeper``