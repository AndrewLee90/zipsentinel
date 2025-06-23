import json
import requests

API_URL = "API SERVER URL"
INPUT_PATH = "test_006_multilingual.json"
OUTPUT_PATH = "results_clovax_006.json"

def run_test():
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    results = []
    print(f"📦 테스트 케이스 수: {len(test_cases)}")

    for case in test_cases:
        try:
            response = requests.post(API_URL, json={"post_text": case["input_text"]})
            print(f"[{case['id']}] 응답 상태 코드: {response.status_code}, 내용: {response.text}")

            if response.status_code == 200:
                predicted = response.json().get("password", "")
            else:
                predicted = "ERROR"

            results.append({
                "id": case["id"],
                "expected_password": case.get("expected_password", ""),
                "predicted": predicted,
                "match": predicted == case.get("expected_password", "")
            })

        except Exception as e:
            results.append({
                "id": case["id"],
                "expected_password": case.get("expected_password", ""),
                "predicted": "EXCEPTION",
                "match": False,
                "error": str(e)
            })

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"✅ 완료: 결과가 {OUTPUT_PATH}에 저장되었습니다.")

if __name__ == "__main__":
    run_test()
