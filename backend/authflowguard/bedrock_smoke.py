"""Run one deliberately small live Bedrock structured-action request."""

import argparse

from botocore.exceptions import ClientError

from authflowguard.bedrock import (
    BedrockActionClient,
    BedrockConfiguration,
    ObservedControlForModel,
    PageObservationForModel,
)


def read_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one bounded AuthFlowGuard Bedrock smoke request."
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument(
        "--confirm-live-call",
        action="store_true",
        help="Required acknowledgement that this request may incur a small charge.",
    )
    return parser.parse_args()


def main() -> None:
    arguments = read_arguments()
    if not arguments.confirm_live_call:
        raise SystemExit("Add --confirm-live-call to run the billable smoke request.")

    configuration = BedrockConfiguration(
        aws_profile=arguments.profile,
        aws_region=arguments.region,
        model_id=arguments.model_id,
        max_output_tokens=128,
        maximum_estimated_cost_usd=0.001,
    )
    observation = PageObservationForModel(
        page_url="https://example.test/login?temporary_code=never-send-this",
        page_title="Login",
        controls=[
            ObservedControlForModel(
                observed_control_id="control-1",
                tag="input",
                name="username",
                control_type="text",
                autocomplete="username",
            )
        ],
        credential_references=["known-account-username"],
    )

    try:
        decision = BedrockActionClient(configuration).choose_action(observation)
    except ClientError as error:
        aws_error = error.response.get("Error", {})
        error_code = aws_error.get("Code", "UnknownAwsError")
        error_message = aws_error.get("Message", "No error details were returned")
        raise SystemExit(
            f"Bedrock request failed ({error_code}): {error_message}"
        ) from error

    print("Bedrock structured-action smoke test succeeded.")
    print(f"Action type: {decision.action.action_type.value}")
    print(f"Input tokens: {decision.input_tokens}")
    print(f"Output tokens: {decision.output_tokens}")
    print(f"Estimated actual cost (USD): {decision.actual_cost_usd:.8f}")
    print(f"Reserved maximum cost (USD): {decision.reserved_cost_usd:.8f}")


if __name__ == "__main__":
    main()
