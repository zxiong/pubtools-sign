#!/usr/bin/python

from __future__ import absolute_import, division, print_function

import os

from ansible.module_utils.basic import AnsibleModule

from ..conf.conf import load_config
from ..operations.clearsign import ClearSignOperation
from ..signers.msgsigner import MsgSigner, _get_config_file

__metaclass__ = type

doc_arguments = ClearSignOperation.doc_arguments()

DOCUMENTATION = r"""
---
module: clear_sign
version_added: "0.1"
short_description: This is used to do clear sign
description:
    - Sign data with clear sign.
options:
    inputs:
        description: {0}.
        required: true
        type: list
    signing_key:
        description: {1}.
        required: true
        type: str
    task_id:
        description: {2}.
        required: true
        type: str
    config:
        description: 
            - Config file path.
            - By default, it will read from "~/.config/pubtools-sign/conf.yaml" or "/etc/pubtools-sign/conf.yaml"
        required: false
        type: str   
extends_documentation_fragment:
    - action_common_attributes
attributes:
    check_mode:
        support: full
    diff_mode:
        support: none
    platform:
        platforms: posix
author:
    - zxiong (@redhat.com)
""".format(
    doc_arguments.get("inputs"),
    doc_arguments.get("signing_key"),
    doc_arguments.get("task_id"),
)

EXAMPLES = r"""
# Pass in a message
- name: clear sign
  clear_sign:
    inputs: 
      - "input1"
      - "input2"
    signing_key: "123"
    task_id: "1"
    config: "/etc/pubtools-sign/conf.yaml"

The example of the config file /etc/pubtools-sign/conf.yaml:
msg_signer:
  messaging_brokers:
    - amqps://broker-01:5671
    - amqps://broker-02:5671
  messaging_cert: {f_client_certificate}
  messaging_ca_cert: ~/messaging/ca-cert.crt
  topic_send_to: topic://Topic.sign
  topic_listen_to: queue://Consumer.{{creator}}.{{task_id}}.Topic.sign.{{task_id}}
  environment: prod
  service: pubtools-sign
  timeout: 1
  retries: 3
  message_id_key: request_id
  log_level: debug
"""

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return values.
signer_result:
    description: clear sign results.
    type: dict
    returned: always
    sample: {'status': 'ok', 'error_message": ''}
operation_results:
    description: The signing key which is used during signing.
    type: dict
    returned: always
    sample: ["signed:'hello world'"]
signing_key:
    description: The signing key which is used during signing.
    type: str
    returned: always
    sample: '123'
"""


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        inputs=dict(type="list", required=True),
        signing_key=dict(type="str", required=True),
        task_id=dict(type="str", required=True),
        config=dict(type="str", required=False),
    )

    result = dict(changed=False, message="")
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    inputs = module.params["inputs"]
    signing_key = module.params["signing_key"]
    task_id = module.params["task_id"]
    config = module.params["config"]

    # Call clear sign and return signed data
    try:
        msg_signer = MsgSigner()
        config = _get_config_file(config)
        msg_signer.load_config(load_config(os.path.expanduser(config)))

        str_inputs = []
        for input_ in inputs:
            if input_.startswith("@"):
                str_inputs.append(open(input_.lstrip("@")).read())
            else:
                str_inputs.append(input_)
        operation = ClearSignOperation(
            inputs=str_inputs, signing_key=signing_key, task_id=task_id
        )
        clear_signing_result = msg_signer.sign(operation)
        signing_result = {
            "signer_result": clear_signing_result.signer_results.to_dict(),
            "operation_results": clear_signing_result.operation_result.outputs,
            "signing_key": clear_signing_result.operation_result.signing_key,
        }
    except Exception as ex:
        module.fail_json(msg=str(ex), exception=ex)

    result["message"] = signing_result

    # signing failed
    if signing_result["signer_result"]["status"] != "ok":
        module.fail_json(msg=signing_result["signer_result"]["error_message"], **result)

    # signing successfully
    result["changed"] = True
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()

