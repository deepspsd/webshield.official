import traceback
from pathlib import Path
import joblib


def main() -> None:
    models_dir = Path(__file__).parent / "saved_models"
    print(f"Scanning {models_dir.resolve()}")
    if not models_dir.exists():
        print("Models directory does not exist.")
        return

    for model_path in sorted(models_dir.glob("*.joblib")):
        print("\nLoading:", model_path.name)
        try:
            obj = joblib.load(model_path)
            print("OK:", type(obj))
        except Exception as exc:
            print("FAILED:", repr(exc), "type=", type(exc))
            traceback.print_exc()


if __name__ == "__main__":
    main()
