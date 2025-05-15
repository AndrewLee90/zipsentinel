##  "collected_at": "2025-05-15 20:17:52" 데이터가 나오지 않는 상황 수정 방법 ##
## 시간 import 및 result 함수 구체화하기  ##

#🔧 기존 코드 예시 (단순화):

def process_post(post_url, driver, session):
    ...
    result = {
        "title": title,
        "author_id": author_id,
        "post_url": post_url,
        "files": extracted_files,
        ...
    }
    return result

# ✅수정된 코드 단락:

from datetime import datetime  # 📌 상단 import 필요

def process_post(post_url, driver, session):
    ...
    result = {
        "title": title,
        "author_id": author_id,
        "post_url": post_url,
        "files": extracted_files,
        ...
        "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 🆕 추가
    }
    return result



### 추가사항 ###

📝 ZIPSentinel 2.1.2 이후 Python 코드 수정 메모 목록
✅ 1. process_post()에 "collected_at" 필드 추가
위치: result 딕셔너리에 "collected_at" 필드 삽입

형식: datetime.now().strftime("%Y-%m-%d %H:%M:%S")

목적: 게시글 단위 수집 시점 기록

✅ 반영 코드:

python
복사
편집
from datetime import datetime

result = {
    ...
    "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}
✅ 2. logging 설정을 log.txt 파일에도 기록되도록 변경
위치: logging.basicConfig() 설정부

변경 이유: Python 실행 로그가 stdout으로만 나가고 있어서 파일에 저장되지 않음

✅ 반영 코드:

python
복사
편집
import logging
import os

LOG_FILE = os.path.join(os.getcwd(), "log.txt")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
✅ 3. (선택) 로그 저장 위치 변경 시 backup_watcher.sh도 수정 필요
log.txt 경로가 바뀌면 백업 스크립트의 이 부분도 함께 수정:

bash
복사
편집
docker cp crawler-2.1.2:/app/log.txt $TARGET_DIR/log.txt
🔧 부가 사항 (반영은 선택)
항목	상태	설명
save_result() 구조	✅ 문제 없음	이미 리스트 append 구조로 잘 작성되어 있음
누락 필드 확인	🟡 collected_at 외에는 정상	향후 post_id, category 등 보강 가능

📦 요약: 수정 대상 파일 목록
파일명	수정 내용
crawler2.1.2.py	process_post() + logging 설정
backup_watcher.sh	(log.txt 경로 변경 시만) 동기화 필요

