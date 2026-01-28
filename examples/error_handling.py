"""Error handling examples for Vigil Guard SDK."""

import os

from vigil import (
    Vigil,
    VigilAuthenticationError,
    VigilBatchPartialFailure,
    VigilConfigurationError,
    VigilConnectionError,
    VigilError,
    VigilRateLimitError,
    VigilRetryBudgetExceeded,
    VigilServiceError,
    VigilTimeoutError,
    VigilValidationError,
)

DEFAULT_API_KEY = "vg_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
DEFAULT_BASE_URL = "https://api.vigilguard.customer.domain"


def handle_all_errors():
    """Comprehensive error handling."""
    try:
        client = Vigil(
            api_key=os.environ.get("VIGIL_GUARD_API_KEY", DEFAULT_API_KEY),
            base_url=os.environ.get("VIGIL_GUARD_BASE_URL", DEFAULT_BASE_URL),
        )
        result = client.detect("Please reset my password for account 18473")
        print(f"Success: {result.decision}")

    except VigilConfigurationError as e:
        print(f"Configuration error: {e}")
        print("Check your API key and base_url settings")

    except VigilAuthenticationError as e:
        print(f"Authentication failed: {e}")
        print("Verify your API key is valid")

    except VigilValidationError as e:
        print(f"Validation error: {e}")
        print(f"Invalid fields: {e.errors}")

    except VigilRateLimitError as e:
        print(f"Rate limited: {e}")
        print(f"Retry after: {e.retry_after} seconds")
        print(f"Limit: {e.limit}")

    except VigilTimeoutError as e:
        print(f"Request timed out: {e}")
        print("Consider increasing timeout")

    except VigilRetryBudgetExceeded as e:
        print(f"Retry budget exceeded: {e}")
        print("Consider lowering max_retries or increasing retry_budget")

    except VigilConnectionError as e:
        print(f"Connection failed: {e}")
        print("Check network connectivity")

    except VigilServiceError as e:
        print(f"Server error: {e}")
        print("API is temporarily unavailable")

    except VigilError as e:
        print(f"General error: {e}")


def handle_batch_failures():
    """Handle partial batch failures."""
    from vigil import BatchItem

    try:
        client = Vigil(
            api_key=os.environ.get("VIGIL_GUARD_API_KEY", DEFAULT_API_KEY),
            base_url=os.environ.get("VIGIL_GUARD_BASE_URL", DEFAULT_BASE_URL),
        )

        items = [
            BatchItem(text="Please reset my password"),
            BatchItem(text=""),  # Invalid - empty
            BatchItem(text="Summarize this support ticket"),
        ]

        result = client.batch(items)

        if result.has_failures:
            print(f"Partial failure: {result.succeeded}/{result.total} succeeded")

            for failed in result.failed_items():
                if failed.error:
                    print(f"  Item {failed.index}: {failed.error.code} - {failed.error.message}")

            for success in result.successful_items():
                if success.result:
                    print(f"  Item {success.index}: {success.result.decision}")

        # Or raise if any failures
        result.raise_for_failures()

    except VigilBatchPartialFailure as e:
        print(f"Batch failed: {e}")
        print(f"Successful: {e.successful}")
        print(f"Failed: {e.failed}")


def retry_with_backoff():
    """Example of custom retry logic."""
    import time

    max_attempts = 3
    base_delay = 1.0

    client = Vigil(
        api_key=os.environ.get("VIGIL_GUARD_API_KEY", DEFAULT_API_KEY),
        base_url=os.environ.get("VIGIL_GUARD_BASE_URL", DEFAULT_BASE_URL),
        max_retries=0,  # Disable built-in retries
    )

    for attempt in range(max_attempts):
        try:
            result = client.detect("Please reset my password for account 18473")
            print(f"Success on attempt {attempt + 1}: {result.decision}")
            break

        except VigilRateLimitError as e:
            delay = e.retry_after or (base_delay * (2**attempt))
            print(f"Rate limited, waiting {delay}s...")
            time.sleep(delay)

        except VigilServiceError:
            delay = base_delay * (2**attempt)
            print(f"Server error, retrying in {delay}s...")
            time.sleep(delay)

        except VigilError as e:
            print(f"Unrecoverable error: {e}")
            break
    else:
        print("All attempts failed")


def main():
    """Run error handling examples."""
    print("=== Comprehensive Error Handling ===")
    handle_all_errors()

    print("\n=== Batch Failure Handling ===")
    handle_batch_failures()

    print("\n=== Custom Retry Logic ===")
    retry_with_backoff()


if __name__ == "__main__":
    main()
