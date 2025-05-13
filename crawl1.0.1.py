import os  # 파일 및 경로 조작
import time  # 시간 관련 함수 (파일명에 사용)
import hashlib  # 파일 해시 계산
import mimetypes  # 파일 확장자 추론
import re  # 정규식 처리
import json  # JSON 입출력
import logging  # 로깅 처리
import requests  # HTTP 요청
from selenium import webdriver  # 셀레니움 웹드라이버
from selenium.webdriver.common.by import By  # 요소 탐색 방식
from selenium.webdriver.support.ui import WebDriverWait  # 요소 대기
from selenium.webdriver.support import expected_conditions as EC  # 대기 조건
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException  # 예외 처리
from requests.adapters import HTTPAdapter  # 요청 어댑터
from urllib3.util.retry import Retry  # 재시도 정책

# ======================= 설정 =======================
MAIN_URL = "https://ko.taiwebs.com/windows"
DOMAIN = "https://ko.taiwebs.com"
MAX_PAGES = 10
URLS_FILE = "posts.json"
OUTPUT_FILE = "data.1.json"
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

# 설정 = (상수 변수 설정 블록)은 재사용성, 확장성, 유지보수 유리, 테스트 및 자동화에 유리하게 하기 위한 설계
# 다양한 변수에 유연하게 대처하고 불필요한 코드 수정을 최소화 하기 위한 전략적 설계
# 더 자세한 설명의 경우 ##region 옆의 토글을 눌러 확인

# ======================= 로깅 설정 =======================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("crawler.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

#region 로깅의 뜻 및 작성한 이유

# 프로그램의 실행 흐름, 상태, 에러를 텍스트 파일이나 콘솔에 기록하여 
# 문제 발생 시 원인 파악 및 수정에 도움을 줄 수 있는 이력 남기기.
# 로깅은 에러 추적 + 디버깅 + 실행 이력 기록을 위한 강력한 실무 도구

# 구성 요소	역할
# level=logging.INFO	INFO, WARNING, ERROR, DEBUG 중에서 어느 수준 이상을 출력할지 지정.
# format=...	로그 메시지의 형식을 지정. (시간, 수준, 메시지 포함)
# FileHandler	로그를 crawler.log 파일에 기록 (한글 깨짐 방지를 위해 utf-8 인코딩)
# StreamHandler	터미널/콘솔에도 실시간 출력

# 포맷 문자열	의미
# %(asctime)s	로그가 기록된 시간. 기본 형식은 YYYY-MM-DD HH:MM:SS,sss
# %(levelname)s	로그의 수준 이름 (DEBUG, INFO, WARNING, ERROR, CRITICAL 중 하나)
# %(message)s	실제 logger.info("메시지")로 전달한 내용

# 예시 [2025-05-04 22:12:01,584] INFO: 게시글 URL 수집 시작
#endregion


# ======================= HTTP 세션 + 재시도 설정 =======================
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

#region 에러 코드 의미 및 설명

# 상태      코드	의미	                        설명
# 429	Too Many Requests	     클라이언트가 너무 많은 요청을 보내서 서버가 잠시 차단한 상태입니다. 주로 API Rate Limit 초과 시 발생합니다.
# 500	Internal Server Error	 서버 내부 에러. 일반적으로 서버 쪽에서 처리 중 문제가 발생했을 때 응답합니다.
# 502	Bad Gateway	             게이트웨이 또는 프록시 서버가 잘못된 응답을 받았을 때 발생합니다. 즉, 중간 서버가 원 서버로부터 제대로 된 응답을 받지 못한 경우입니다.
# 503	Service Unavailable	     서버가 일시적으로 과부하이거나 유지보수 중일 때 발생합니다. 나중에 다시 시도하면 성공할 수 있는 상태입니다.
# 504	Gateway Timeout	         게이트웨이 또는 프록시 서버가 원 서버로부터 응답을 받지 못해 시간 초과된 경우입니다. 네트워크 지연이나 서버 응답 지연이 원인일 수 있습니다.

#endregion

# ======================= Selenium 옵션 =======================
options = webdriver.ChromeOptions()
options.add_argument("--headless")
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--blink-settings=imagesEnabled=false")
options.add_argument("--disable-extensions")
options.add_argument("--disable-plugins")
options.add_argument("--log-level=3")
options.add_argument(
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36"
)
options.add_experimental_option("excludeSwitches", ["enable-automation"])
options.add_experimental_option("useAutomationExtension", False)

#region Selenium WebDriver에서 안정적으로 자동화+크롤링하기 위한 옵션
# 크롤링 속도 향상 + 브라우저 자동화 탐지 회피 + 리소스 최소화 + 에러방지 + 관리 용이 (높은 확장성) 기대할 수 있음

#      옵션	                                        의미	                                       목적
# --headless	                            브라우저를 GUI 없이 백그라운드에서 실행	        속도 ↑, 서버 환경에서도 실행 가능
# --disable-gpu	                            GPU 렌더링 비활성화	                         헤드리스 환경에서 충돌 방지
# --no-sandbox	                            샌드박스 보안 기능 비활성화	                   일부 리눅스 환경에서 충돌 방지
# --disable-dev-shm-usage	                /dev/shm 공유 메모리 사용 안 함	              Docker·Linux에서 메모리 이슈 방지
# --blink-settings=imagesEnabled=false	    이미지 로딩 비활성화                          속도 ↑, 불필요한 자원 ↓
# --disable-extensions	                    크롬 확장 프로그램 비활성화	                   에러 및 간섭 제거
# --disable-plugins	                        플러그인 비활성화	                          무거운 요소 제거로 속도 향상
# --log-level=3	                            크롬 드라이버 로그 최소화	                   로그 출력 줄이기 (INFO 이하 무시)
# user-agent=...	                        일반 브라우저처럼 위장	                       크롤링 탐지 우회용

#endregion


# ======================= 유틸리티 함수 =======================
def calculate_sha256(path):
    hash_obj = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def get_file_extension(filename):
    if filename.lower().endswith(".tar.gz"):
        return ".tar.gz"
    return os.path.splitext(filename)[1] or "N/A"

def ensure_directory(path):
    os.makedirs(path, exist_ok=True)

#region 유틸리티 함수는 파일 처리와 에러 최적화를 위한 핵심 도구
# 코드 중복을 없애고, 안전성을 높이는 역할을 함

# 다운로드한 파일의 변조 여부 확인
# VirusTotal API와 연동 시 해시값 조회용
# 동일 파일 중복 저장 방지 등에도 활용 가능

# 1. calculate_sha256(path)

#       코드	                                설명
# hashlib.sha256()	                    SHA-256 해시 객체 생성
# open(path, 'rb')	                    파일을 바이너리 읽기 모드로 염
# iter(lambda: file.read(8192), b'')	8KB씩 읽어 끝날 때까지 반복
# hash_obj.update(chunk)	            읽은 내용을 해시에 추가
# return ...hexdigest()	                최종 해시값을 16진수 문자열로 반환

# 2. get_file_extension(filename)

# 파일명에서 확장자만 추출하는 함수
# .tar.gz 같은 불특정 다수의 확장자를 정확히 구분하기 위한 로직

# .zip, .rar, .exe 등을 구분하여 파일 유형 확인
# 필터링이나 보안 분석 로직에 활용
# 일부 서버는 확장자 없이 내려주기도 해서 직접 추출해야 함

# 3. ensure_directory(path)
# 지정된 경로에 디렉토리가 없으면 자동으로 생성
# 존재할 경우에는 아무 작업도 하지 않음

# 경로 이슈로 인한 에러 대비 
# 테스트 & 운영 환경에서 디렉토리 여부 신경 안 써도 됨
# exist_ok=True 덕분에 이미 존재해도 에러 발생 X
# 도커 이슈 최소화

#endregion

# ======================= 1단계: 게시글 URL 수집 =======================
def collect_post_urls(driver):
    post_urls = []
    for page in range(1, MAX_PAGES + 1):
        url = MAIN_URL if page == 1 else f"{MAIN_URL}/?page={page}"
        try:
            logger.info(f"[페이지 {page}/{MAX_PAGES}] 로딩 중: {url}")
            driver.get(url)
        except TimeoutException:
            logger.warning(f"페이지 {page} 로딩 시간 초과")
            continue
        try:
            anchors = driver.find_elements(By.CSS_SELECTOR, "h3.title a")
            for anchor in anchors:
                href = anchor.get_attribute("href") or ''
                if href.startswith(f"{DOMAIN}/windows/download-"):
                    post_urls.append(href)
        except WebDriverException as e:
            logger.warning(f"페이지 {page} URL 수집 실패: {e}")
    unique_urls = list(dict.fromkeys(post_urls))
    with open(URLS_FILE, 'w', encoding='utf-8') as f:
        json.dump(unique_urls, f, ensure_ascii=False, indent=2)
    logger.info(f"총 {len(unique_urls)}개의 게시글 URL 수집 완료")
    return unique_urls


#region 크롤링 개시 단계, 변수 Error에 대한 대응 및 유지보수 원할하게 하기 위한 함수 정의
# 지정한 페이지 수 만큼 게시글 URL 수집 및 저장, Selenium/json 저장 + 중복 사항 제거
# 수집된 URL 리스트를 비나, 실제 게시글 내용을 수집하기 쉬움


# 1. for page in range(1, MAX_PAGES + 1):
        #url = MAIN_URL if page == 1 else f"{MAIN_URL}/?page={page}"
# 첫 페이지는 URL이 다르기 때문에 조건문으로 분리
# 향후 MAX_PAGES만 수정하면 자동으로 순회 범위가 바뀜

# 2. if href.startswith(f\"{DOMAIN}/windows/download-\"):
# 광고, 내부 페이지 등을 걸러내고
# 실제로 다운로드 가능한 게시글만 추출

# 3. unique_urls = list(dict.fromkeys(post_urls))
# Pythonic한 방식으로 중복 제거 (dict의 key는 유일)
# 결과는 posts.json으로 저장 → 다음 단계에서 재사용 가능

# 4. 필요에 따라 CSV 형식으로도 활용 가능
# import pandas as pd
# pd.DataFrame(unique_urls).to_csv('posts.csv', index=False)

#endregion

# ======================= 2단계: 게시글 처리 =======================
def process_post(post_url, driver):
    try:
        driver.get(post_url)
        title = WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, 'h1.text-big span.sw-name'))
        ).text.strip()
        logger.info(f"처리 중: {title}")

        author_id = extract_author_id(driver)

        dl_button = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'a.box-down-bottom'))
        )
        intermediate_url = dl_button.get_attribute('href')
        driver.get(intermediate_url)

        try:
            skip_ad = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, '.ad_skip, .skip-btn, #skip-ad, button.skip-ad, .close-btn'))
            )
            skip_ad.click(); time.sleep(1)
        except Exception:
            pass

        time.sleep(1)
        links = collect_download_links(driver)
        if not links:
            raise ValueError("다운로드 링크 없음")

        ensure_directory(DOWNLOAD_DIR)
        files_info = [download_and_hash_file(link) for link in links]

        try:
            password = driver.find_element(By.CSS_SELECTOR, 'span#password_rar').text.strip()
        except NoSuchElementException:
            password = 'taiwebs.com'

        match = re.search(r'download-.*-(\d+)\.html$', post_url)
        doc_number = match.group(1) if match else 'N/A'

        return {
            'title': title,
            'author_id': author_id,
            'source_url': intermediate_url,
            'doc_number': doc_number,
            'password': password,
            'files': files_info
        }
    except Exception as error:
        logger.error(f"오류 발생: {post_url} -> {error}")
        return None


#region 7단계 시퀀스 게시글 열기 > 제목 추출 > 작성자 ID 추출 > 다운로드 페이지 진입 > 광고 스킵 > 다운로드 링크 추출 > 파일 다운로드 + 메타 정보 계산
# 게시글 1건 마다 다운로드 가능한 정보+파일+해시값 수집
# Selenium 대기, CSS 선택자, 파일 다운로드, 정규표현식
# 변수 관리 + 정보 수집 원활
#
# 1. driver.get(post_url)
#    title = WebDriverWait(driver, 15).until(
#    EC.visibility_of_element_located((By.CSS_SELECTOR, 'h1.text-big span.sw-name'))
#    ).text.strip()
#
#       목적	                            설명
# driver.get(post_url)	            게시글 페이지 로드
# WebDriverWait(...).until(...)	    최대 15초 동안 해당 요소가 나타날 때까지 대기
# title	                            소프트웨어 제목 (UI상 가장 큰 텍스트 영역)
# strip()                           좌우 공백 제거
# 
# 2. 작성자 ID 추출
# author_id = extract_author_id(driver)
# 작성자의 정보가 페이지에 표시된다면, CSS 선택자로 찾는 함수
# extract_author_id()는 별도 유틸로 분리되어 있을 것
#
# 3. 다운로드 버튼 → 중간 URL 진입
# dl_button = WebDriverWait(driver, 15).until(
    #EC.element_to_be_clickable((By.CSS_SELECTOR, 'a.box-down-bottom'))
# )
# intermediate_url = dl_button.get_attribute('href')
# driver.get(intermediate_url)
#
#      동작	                    설명
# dl_button	                다운로드 버튼 대기
# get_attribute('href')	    실제 다운로드 페이지 URL 추출
# driver.get(...)	        다운로드 페이지로 이동
#
# 4. 광고 스킵 시도
# try:
#    skip_ad = WebDriverWait(driver, 5).until(
#        EC.element_to_be_clickable((By.CSS_SELECTOR, '.ad_skip, .skip-btn, #skip-ad, button.skip-ad, .close-btn'))
#    )
#    skip_ad.click(); time.sleep(1)
# except Exception:
#     pass
#
# 광고창이나 중간 팝업 스킵	다양한 클래스명을 고려한 CSS 선택자 설정
# time.sleep(1)	클릭 후 로딩 대기 시간
# 광고창 미발견 등의 변수 발생 시, 코드 전체 로직이 중단되지 않도록 except로 무시
#
# 5. 다운로드 링크 수집
# links = collect_download_links(driver)
# if not links:
#     raise ValueError("다운로드 링크 없음")
#
# 수집된 다운로드 링크가 없으면 명시적으로 에러 발생시켜 무시되도록 함
# collect_download_links() 함수가 실제 .exe, .zip 링크를 찾아 반환
#
# 6. 파일 다운로드 + 해시 계산
# ensure_directory(DOWNLOAD_DIR)
# files_info = [download_and_hash_file(link) for link in links]
# 
#       함수	                                기능
# ensure_directory()	      저장 디렉토리 없으면 생성
# download_and_hash_file()	  각 파일을 다운로드하고 SHA-256 해시 및 확장자 반환
#
# 7. 비밀번호 추출
# try:
#    password = driver.find_element(By.CSS_SELECTOR, 'span#password_rar').text.strip()
# except NoSuchElementException:
#    password = 'taiwebs.com'
# 
# 일반적으로는 span#password_rar 요소에서 패스워드 추출
# 없다면 기본값으로 taiwebs.com 설정 (기본 비밀번호)
#
# 8. 게시글 번호 추출
# match = re.search(r'download-.*-(\d+)\\.html$', post_url)
# doc_number = match.group(1) if match else 'N/A'
#
#게시글의 고유번호를 URL에서 정규식으로 추출
#실패 시 'N/A' 처리
#
# 9. 최종 결과 리턴
#
# return {
#    'title': title,
#    'author_id': author_id,
#    'source_url': intermediate_url,
#    'doc_number': doc_number,
#    'password': password,
#    'files': files_info
# }
#
# 하나의 게시글에서 추출한 모든 핵심 정보를 딕셔너리로 반환 → 저장에 사용
#
# 9-1 예외 처리
# except Exception as error:
#    logger.error(f"오류 발생: {post_url} -> {error}")
#    return None
# 
# 에러 발생 시 None을 반환 > 메인 루프에서 건너뜀
# 추후 문제 해결을 위해 에러 메시지와 URL을 모두 로깅
#endregion


def extract_author_id(driver):
    try:
        for li in driver.find_elements(By.CSS_SELECTOR, 'li'):
            txt = li.text.strip()
            if '게시자' in txt:
                parts = re.split(r'[:：]\s*', txt, maxsplit=1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
    except Exception:
        pass
    try:
        name_elem = driver.find_element(By.CSS_SELECTOR, 'span[itemprop="name"]')
        name = name_elem.text.strip()
        if name and name != '홈페이지':
            return name
    except NoSuchElementException:
        pass
    try:
        for row in driver.find_elements(By.CSS_SELECTOR, 'table tbody tr'):
            if '작성자' in row.find_element(By.TAG_NAME, 'th').text:
                return row.find_element(By.TAG_NAME, 'td').text.strip()
    except Exception:
        pass
    return 'N/A'

#region 게시글 내, 작성자 정보 추출, 다운로드 링크 추출 보조 함수, HTML 구조의 변수가 있을 시, 유연하게 대처 하기 위한 변수 지정
# 
# 모든 단계에서 변수 발생 시, 무시하고 다음 방식을 시도
# 최종적으로 아무정보를 찾지 못했을 시, 크래시가 아닌 'N/A'를 반환하는 로직
# 
# 
# 1. extract_author_id(driver)
# 게시글에서 작성자(게시자) 정보를 찾아 문자열로 반환, 구조가 일정하지 않음을 고려해 다양한 방식으로 시도
# 
# for li in driver.find_elements(By.CSS_SELECTOR, 'li'):
#    txt = li.text.strip()
#    if '게시자' in txt:
#        parts = re.split(r'[:：]\s*', txt, maxsplit=1)
#        if len(parts) == 2 and parts[1].strip():
#            return parts[1].strip()
#
#   동작	                                        설명
# li 반복 탐색	                    리스트 항목들 중 '게시자' 포함 항목 찾기
# re.split(...)	                   : 또는 ： 기준으로 나눔 (한글/영문 지원)
# 값 추출	                        '게시자: ABC' 형태일 때 오른쪽 값 반환
# 
# 2. name_elem = driver.find_element(By.CSS_SELECTOR, 'span[itemprop="name"]')
# name = name_elem.text.strip()
# if name and name != '홈페이지':
#     return name
# 
#    동작	                                        설명
# itemprop="name"	                구조화된 데이터 마크업에 사용되는 표준 속성
# "홈페이지" 필터	                  무의미한 텍스트 거르기
# 
# 3. for row in driver.find_elements(By.CSS_SELECTOR, 'table tbody tr'):
#    if '작성자' in row.find_element(By.TAG_NAME, 'th').text:
#        return row.find_element(By.TAG_NAME, 'td').text.strip()
#
#   동작	                                        설명
# 테이블 구조 내 '작성자' 항목 탐색	     <th>작성자</th><td>홍길동</td> 형식에 대응
#
#endregion


def collect_download_links(driver):
    links = []
    for a in driver.find_elements(By.TAG_NAME, 'a'):
        href = a.get_attribute('href') or ''
        if re.search(r'\.(exe|zip|rar|msi|7z|tar\.gz)(?:\?.*)?$', href):
            links.append(href)
    for a in driver.find_elements(By.XPATH, '//a[starts-with(@id,"various")] | //a[contains(@onclick,"myfunctions_s")]'):
        href = a.get_attribute('href') or ''
        if href and href not in links:
            links.append(href)
    if not links:
        matches = re.findall(r'(https?://[^"\s]+?\.(?:exe|zip|rar|msi|7z|tar.gz)(?:\?[^"\s]*)?)', driver.page_source)
        links = list(dict.fromkeys(matches))
    return links

#region 용어설명 + 게시글 페이지내, 다운로드 가능한 파일 (exe, zip 등등)의 링크를 확정 추출, CSS + XPath + Page source 3단계 구성, 중복 제거, fallback 처리, 정규식 활용
#
# 용어설명
#
# CSS 선택자 (CSS Selector) : HTML 태그를 선택할 때 사용하는 문법 / 브라우저에서 보이는 구조 그대로 태그 탐색 가능
# XPath (경로탐색자) : HTML을 폴더 경로 방식으로 탐색하는 방법, CSS로는 못잡는 특수한 상황에 대응할 수 있는 보조 수단, (id가 'various로 시작하는 <a> 태그')
# <a> / </a>는 HTML에서 하이퍼링크를 의미, URL링크 + 다운로드 버튼등에 사용
# Page Source (HTML 원문 분석) : 페이지 전체 HTML코드를 문자열로 읽어, 그 안에서 링크를 찾는 방식. CSS, Xpath 모두 실패 시, 와일드카드로 사용. JS기반 페이지에서 효과적
# Fallback 처리 (대비책, plan B) : 앞에서 시도한 방법이 실패할 시, 작동하는 보조 계획
# 정규식 활용 : 문자열에서 내가 원하는 패턴을 뽑아내는 도구, zip, exe과 같은 링크를 일일이 찾는 게 아니라 자동으로 걸러낼 수 있음
# 
#                         요약
#
#   용어	                뜻	                   예시
# CSS Selector	    화면 구조 기반 선택자	     div > a.title
# XPath	            경로 기반 탐색	            //a[@id='download']
# Page Source	    페이지 전체 HTML 코드	    driver.page_source
# Fallback	        실패할 경우 대비책	        A → B → C 순차 시도
# 정규식표현	      패턴 추출 도구	            .zip, .exe 주소만 뽑기
# 
# 1. for a in driver.find_elements(By.TAG_NAME, 'a'):
#    href = a.get_attribute('href') or ''
#    if re.search(r'\.(exe|zip|rar|msi|7z|tar\.gz)(?:\?.*)?$', href):
#        links.append(href)
#
#   동작	                                       설명
# 모든 <a> 태그 탐색	                직접 링크되어 있는 다운로드 파일 필터
# 정규식	                 .exe, .zip, .rar, .tar.gz 등 확장자로 끝나는 URL만 추출
#
# 2. for a in driver.find_elements(By.XPATH, '//a[starts-with(@id,"various")] | //a[contains(@onclick,"myfunctions_s")]'):
#    href = a.get_attribute('href') or ''
#    if href and href not in links:
#        links.append(href)
# 
#   동작	                                       설명
# XPATH로 버튼 기반 링크 추출	        JavaScript 다운로드 함수 등 동적 다운로드 대응
# 중복 제거	                                이미 수집된 링크는 제외
#
# 3. if not links:
#    matches = re.findall(r'(https?://[^"\\s]+?\.(?:exe|zip|rar|msi|7z|tar.gz)(?:\?[^"\\s]*)?)', driver.page_source)
#    links = list(dict.fromkeys(matches))
# 
#   동작	                                        설명
# 링크가 아무것도 없을 경우	            HTML 원문에서 직접 링크 문자열 추출 (fallback)
# 중복 제거	                          dict.fromkeys()로 순서 유지하며 중복 제거
#
#
#  
#endregion


def download_and_hash_file(link):
    try:
        response = session.get(link, timeout=120)
        response.raise_for_status()
        cd = response.headers.get('content-disposition','')
        match = re.search(r'filename="?([^";]+)"?', cd)
        if match:
            fname = match.group(1)
        else:
            path = requests.utils.urlparse(response.url).path
            fname = os.path.basename(path)
        root, ext = os.path.splitext(fname)
        if not ext:
            ctype = response.headers.get('Content-Type','').split(';')[0]
            ext = mimetypes.guess_extension(ctype) or ''
            fname = root + ext
        full_path = os.path.join(DOWNLOAD_DIR, fname)
        with open(full_path, 'wb') as f:
            f.write(response.content)
        file_hash = calculate_sha256(full_path)
        os.remove(full_path)
        return {'url': link, 'filename': fname, 'sha256': file_hash, 'extension': get_file_extension(fname)}
    except Exception as e:
        logger.error(f"다운로드 실패: {link} -> {e}")
        return {'url': link, 'filename': 'N/A', 'sha256': 'N/A', 'extension': 'N/A'}
    
#region 다운로드링크를 활용 > 정보 수집 (파일이름, 확장자, SHA-256 해시값) > 파일 삭제 
# 다양한 파일명 형식, 응닶 없음, 확장자 없음 등 메이저 이슈에 유연하게 대응할 수 있도록 코딩.
# 
# 1. response = session.get(link, timeout=120)
# response.raise_for_status()
#
#   동작	                            설명
# session.get(...)	        설정된 세션(재시도 포함)으로 요청
# timeout=120	                최대 2분까지 대기 허용
# raise_for_status()	    4xx 또는 5xx 응답이면 예외 발생 (강제 실패 처리)
#
# 2. cd = response.headers.get('content-disposition', '')
# match = re.search(r'filename="?([^";]+)"?', cd)
#
# 서버가 응답 헤더에 Content-Disposition: attachment; filename="example.zip" 같은 정보를 포함하는 경우, 이 정보를 이용해 실제 다운로드 파일명을 추정
# 
# 3. if match:
#    fname = match.group(1)
# else:
#     path = requests.utils.urlparse(response.url).path
#     fname = os.path.basename(path)
#
# .exe, .zip 같은 확장자가 없는 경우를 위한 보정 로직
# Content-Type이 application/x-msdownload면 .exe로 추정하는 식
# mimetypes.guess_extension()으로 자동 판단
# GPT TIP > 실무에서는 확장자가 없는 링크도 자주 있으므로 꼭 필요한 안전장치
# 
# 4. full_path = os.path.join(DOWNLOAD_DIR, fname)
# with open(full_path, 'wb') as f:
#     f.write(response.content)
#
# 다운로드한 바이너리 파일 데이터 저장
# 이후 해시 계산용으로만 잠깐 사용
# 
# 5. file_hash = calculate_sha256(full_path)
# os.remove(full_path)
# 
# SHA-256 해시값 계산
# 저장공간 보호 및 깔끔한 작업을 위해 즉시 삭제
# 
# 6. return {
#    'url': link,
#    'filename': fname,
#    'sha256': file_hash,
#    'extension': get_file_extension(fname)
# }
#
# 후속 단계에서 이 정보(파일명, 해시, 확장자)가 JSON 저장, 보안 검사, 중복 방지 등에 사용됨
# 
# 7. except Exception as e:
#    logger.error(f"다운로드 실패: {link} -> {e}")
#    return {'url': link, 'filename': 'N/A', 'sha256': 'N/A', 'extension': 'N/A'}
#
# 네트워크 오류, 저장 실패, 디코딩 실패 등 모든 예외에 대응
# 실패하더라도 크롤러 전체가 멈추지 않도록 설계
# 
# 
#endregion

# ======================= MAIN 실행 =======================
def main():
    ensure_directory(DOWNLOAD_DIR)
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(10)
    driver.set_page_load_timeout(60)

    post_urls = collect_post_urls(driver)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f)

    count = 0
    for url in post_urls:
        try:
            data = process_post(url, driver)
            if data:
                with open(OUTPUT_FILE, 'r+', encoding='utf-8') as f:
                    existing = json.load(f)
                    existing.append(data)
                    f.seek(0)
                    json.dump(existing, f, ensure_ascii=False, indent=2)
                    f.truncate()
                count += 1
        except Exception as e:
            logger.error(f"처리 중 예외: {url} -> {e}")
            continue
    logger.info(f"완료! {count}/{len(post_urls)} 개 처리됨")
    driver.quit()

if __name__ == '__main__':
    main()

#region main 함수 정의 : 브라우저 실행 > URL수집 > 각 게시글 다운로드 및 정보 수집 > json 파일 저장 > 드라이버 종료 + 최종 로그 출력
# 
# 1. ensure_directory(DOWNLOAD_DIR)
# 다운로드 파일을 저장할 경로가 없다면 만듬 > 환경에 따른 변수관리
# 무조건 실행 전 환경을 준비하는 초기화 작업
# 
# 2. driver = webdriver.Chrome(options=options)
# driver.implicitly_wait(10)
# driver.set_page_load_timeout(60)
#
# 실서버 환경에서도 튕김 없이 작동하기 위한 안정성 확보 전략
# 
#       구성	                                설명
# webdriver.Chrome(...)	        설정한 옵션(headless, UA 등)을 반영해 크롬 실행
# implicitly_wait(10)	        요소를 찾을 때 최대 10초 기다림 (기본 대기)
# set_page_load_timeout(60)	    전체 페이지가 60초 이내에 로드되지 않으면 Timeout 발생
#
# 3. post_urls = collect_post_urls(driver)
# 
# 이전에 분석한 URL 수집 함수 호출
# 리턴된 리스트를 그대로 저장하고 이후 순회
# 
# 4. with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
#     json.dump([], f)
#
# 결과 저장 파일을 빈 리스트로 초기화
# 나중에 append 방식으로 하나씩 추가해나감
# 
# 5. for url in post_urls:
#    try:
#        data = process_post(url, driver)
# 
# process_post()는 하나의 게시글에서 모든 정보 추출 + 파일 다운로드까지 처리
# 결과 data는 딕셔너리 형태
# 
# 6. with open(OUTPUT_FILE, 'r+', encoding='utf-8') as f:
#    existing = json.load(f)
#    existing.append(data)
#    f.seek(0)
#    json.dump(existing, f, ensure_ascii=False, indent=2)
#    f.truncate()
# 
#       설명	                        의미
# 'r+' 모드	                    읽기 + 쓰기 동시에
# seek(0)	                    파일 맨 앞에서부터 덮어씀
# truncate()	                남아있는 이전 내용 잘라냄
# ensure_ascii=False	        한글도 깨지지 않게 저장
# indent=2	                    예쁘게 들여쓰기된 JSON 파일 생성
# 
# 7. count += 1
# ...
# except Exception as e:
#     logger.error(...)
#     continue
#
# 몇 개 성공했는지 확인
# 실패한 게시글도 무시하고 넘어감 (전체 중단 방지)
# 
# 8. logger.info(f"완료! {count}/{len(post_urls)} 개 처리됨")
# driver.quit()
# 
# 최종 처리 결과 요약 출력
# 브라우저 종료로 리소스 정리
#
#
#endregion
