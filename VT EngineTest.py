import os
import time
import json
import aiohttp
import aiofiles
import hashlib
import asyncio
from datetime import datetime

VT_API_KEY = "개인 API키를 넣어주세요"
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"
DOWNLOAD_DIR = "downloads"
RESULTS_DIR = "results"
LOG_PATH = os.path.join(os.path.dirname(__file__), "vt_engine_log.txt")

os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# 총 12개 파일 × 5회 반복 = 60회 테스트
BASE_TEST_FILES = [
    {"file_name": "vivaldi.zip", "download_url": "https://ko.taiwebs.com/windows/download-vivaldi-159.html", "expected_size": "100MB"},
    {"file_name": "ivt_bluesoleil.zip", "download_url": "https://s2.dl-file.xyz/dl/goo/EIuJauggRB/MTNmLTNoOGxUT05qbHNHNEcyRFpwczJxOGp2dG9vNkdv", "expected_size": "100MB"},
    {"file_name": "studioline_web.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaJJEJ?cod=BhohNzhiBi&ref=U3R1ZGlvTGluZVdlYkRlc2lnbmVyNS4wLjYuZy50YWl3ZWJzLmNvbS56aXA=", "expected_size": "100MB"},
    {"file_name": "virtualdj.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaJJEJ?cod=BhohNzhiBi&ref=U3R1ZGlvTGluZVdlYkRlc2lnbmVyNS4wLjYuZy50YWl3ZWJzLmNvbS56aXA=", "expected_size": "500MB"},
    {"file_name": "cartoon_animator.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEJIJ?cod=BiNNBBBoco&ref=UmVhbGx1c2lvbkNhcnRvb25BbmltYXRvcjUuMzMuNDAwNy4xLmsudGFpd2Vicy5jb20uemlw", "expected_size": "500MB"},
    {"file_name": "ic3d_suite.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEJRB?cod=BhhYBocYBh&ref=Q3JlYXRpdmVFZGdlU29mdHdhcmVpQzNEU3VpdGU4LjAuNS54NjQuZS50YWl3ZWJzLmNvbS56aXA=", "expected_size": "500MB"},
    {"file_name": "movie_studio.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEEEc?cod=BiNoBcYBAY&ref=TUFHSVhWaWRlb0RlbHV4ZTIwMjZQcmVtaXVtMjUuMC4xLjI0Ni5rLnRhaXdlYnMuY29tLnppcA==", "expected_size": "1GB"},
    {"file_name": "photo_studio.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEEEg?cod=BhABhzBcAh&ref=aW5QaXhpb1Bob3RvU3R1ZGlvUHJvMTIuMC42Ljg1My5rLnRhaXdlYnMuY29tLnppcA==", "expected_size": "1GB"},
    {"file_name": "navimodel.zip", "download_url": "https://s2.dl-file.xyz/dl-fast/EIuJaaEEuJ/236075/eWhvaXdvMHBndjg=", "expected_size": "1GB"},
    {"file_name": "coreldraw.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEEgI?cod=BiNozoczAY&ref=Q29yZWxEUkFXR3JhcGhpY3NTdWl0ZTIwMjV2MjYuMS4wLjE0My54NjQudS50YWl3ZWJzLmNvbS56aXA=", "expected_size": "2GB"},
    {"file_name": "indesign.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEBBa?cod=BiAXYhBAzX&ref=QWRvYmVJbkRlc2lnbjIwMjV2MjAuNC4wLjA1Mi54NjRQcmVta3NnLnRhaXdlYnMuY29tLnppcA==", "expected_size": "2GB"},
    {"file_name": "swood.zip", "download_url": "https://sn.dl-faster.xyz/ref/EIuJaaEBca?cod=BiAXYczzNz&ref=RUZJQ0FEU1dPT0QyMDI0U1A0LjAueDY0Zm9yU29saWRXb3JrczIwMTAuMjAyNS5kLnRhaXdlYnMuY29tLnppcA==", "expected_size": "2GB"}
]

REPEAT_COUNT = 5
TEST_FILES = BASE_TEST_FILES * REPEAT_COUNT

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {msg}"
    print(full_msg)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")

async def download_file(session, url, save_path):
    log(f"🔽 다운로드 시작: {url}")
    async with session.get(url) as resp:
        if resp.status != 200:
            raise Exception(f"다운로드 실패: {url}")
        async with aiofiles.open(save_path, mode='wb') as f:
            await f.write(await resp.read())
    log(f"✅ 다운로드 완료: {save_path}")

async def calculate_sha256(file_path):
    log(f"🔍 해시 계산 시작: {file_path}")
    sha256_hash = hashlib.sha256()
    async with aiofiles.open(file_path, 'rb') as f:
        while True:
            chunk = await f.read(4096)
            if not chunk:
                break
            sha256_hash.update(chunk)
    hash_result = sha256_hash.hexdigest()
    log(f"🔐 SHA256 해시: {hash_result}")
    return hash_result

async def query_virustotal(session, sha256):
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}{sha256}"
    log(f"📡 VT 요청 시작: {url}")
    start = time.perf_counter()
    async with session.get(url, headers=headers) as resp:
        t1 = time.perf_counter()
        if resp.status == 200:
            data = await resp.json()
            t2 = time.perf_counter()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            log(f"📊 분석결과: {stats}")
        else:
            data = None
            stats = None
            t2 = t1
            log(f"⚠️ VT 응답 실패: status={resp.status}")

    log(f"⏱️ 응답 시간: {int((t1 - start) * 1000)}ms, 파싱 완료: {int((t2 - start) * 1000)}ms")
    return {
        "status_code": resp.status,
        "analysis_stats": stats,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "timing_ms": {
            "request_start": 0,
            "response_received": int((t1 - start) * 1000),
            "parsing_completed": int((t2 - start) * 1000)
        }
    }

def evaluate(stats, status_code):
    malicious = stats.get("malicious", 0) if stats else 0
    level = "🟢 양호"
    if status_code == 404:
        level = "🟡 미분석"
    elif malicious >= 7:
        level = "🔴 위험"
    elif 3 <= malicious < 7:
        level = "🟠 주의"
    log(f"🎯 등급 평가: {level}")
    return {
        "is_vt_registered": status_code != 404,
        "malicious_threshold_passed": malicious >= 7,
        "notes": level
    }

async def handle_test_file(file_config, session, index):
    file_path = os.path.join(DOWNLOAD_DIR, f"{index}_{file_config['file_name']}")
    try:
        await download_file(session, file_config["download_url"], file_path)
        sha256 = await calculate_sha256(file_path)
        vt_result = await query_virustotal(session, sha256)
        evaluation = evaluate(vt_result["analysis_stats"], vt_result["status_code"])

        log(f"📁 테스트 완료: {file_config['file_name']}")

        return {
            "engine": "VT Analyzer",
            "test_id": f"vt_test_{index}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "file_info": {
                "file_name": file_config["file_name"],
                "expected_size": file_config["expected_size"],
                "file_size_bytes": os.path.getsize(file_path)
            },
            "target_hash": sha256,
            "vt_response": vt_result,
            "evaluation": evaluation
        }

    except Exception as e:
        log(f"❌ 예외 발생: {str(e)}")
        return {
            "engine": "VT Analyzer",
            "file_info": {
                "file_name": file_config["file_name"],
                "expected_size": file_config["expected_size"]
            },
            "error": str(e)
        }

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)
            log(f"🧹 파일 삭제 완료: {file_path}")

async def main():
    async with aiohttp.ClientSession() as session:
        results = []
        for index, file in enumerate(TEST_FILES):
            log(f"[▶] 순차 처리 중 ({index+1}/{len(TEST_FILES)}): {file['file_name']}")
            result = await handle_test_file(file, session, index)
            results.append(result)

        output_path = os.path.join(RESULTS_DIR, f"vt_results_async_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(results, indent=2, ensure_ascii=False))

        log(f"[✅] 모든 결과가 저장되었습니다 → {output_path}")

if __name__ == "__main__":
    asyncio.run(main())
