# ======================= 통합 크롤러 및 자동화 도구 v2.1 =======================
# 기능: 웹페이지 크롤링 → 파일 다운로드 → 압축 해제 → 내부 해시 분석 자동화

import os
import re
import time
import json
import shutil
import hashlib
import logging
import mimetypes
import requests
from pathlib import Path
from zipfile import ZipFile, is_zipfile
import rarfile
import py7zr
import tarfile
import subprocess

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ============= 경로 기준점: 현재 파이썬 파일 위치 =============
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ======================= 크롤러 설정 =======================
CRAWLER_CONFIG = {
    'MAIN_URL': "https://ko.taiwebs.com/windows",
    'DOMAIN': "https://ko.taiwebs.com",
    'MAX_PAGES': 1,
    'URLS_FILE': os.path.join(BASE_DIR, "posts.json"),
    'OUTPUT_FILE': os.path.join(BASE_DIR, "data.2.json"),
    'DOWNLOAD_DIR': os.path.join(BASE_DIR, "downloaded_files"),
}

# ======================= 자동화 설정 =======================
AUTOMATION_CONFIG = {
    'UNZIP_DEPTH': 3,
    'SUPPORTED_EXTENSIONS': ['.zip', '.rar', '.7z', '.tar.gz'],
    'MAX_FILE_SIZE_MB': 1000,
    'MAX_INNER_FILES': 100,
    'VT_LOOKUP_ENABLED': True,
    'REMOVE_AFTER_SCAN': True,
    'FILENAME_ENCODING': 'utf-8',
    'TEMP_CLEANUP_ON_FAIL': True,
    'VT_HASH_ONLY_MODE': True,
    'EXTRACT_DIR': os.path.join(BASE_DIR, "extracted_files"),
    'OUTPUT_FILE': os.path.join(BASE_DIR, "result.processed.json"),
}
# ======================= 로깅 설정 =======================
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("crawler.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ======================= HTTP 세션 설정 =======================
def create_session():
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# ======================= Selenium 옵션 설정 =======================
def create_webdriver_options():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--blink-settings=imagesEnabled=false")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--log-level=3")
    options.add_argument("--disable-webgl")
    options.add_argument("--use-gl=swiftshader")
    options.add_argument("--disable-3d-apis")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36"
    )
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    return options


# ======================= 파일 유틸리티 클래스 =======================
class FileUtils:
    @staticmethod
    def calculate_sha256(path):
        hash_obj = hashlib.sha256()
        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    @staticmethod
    def get_file_extension(filename):
        if filename.lower().endswith(".tar.gz"):
            return ".tar.gz"
        ext = os.path.splitext(filename)[1]
        return ext.lower() if ext else "N/A"

    @staticmethod
    def is_tar_gz(filename):
        return filename.lower().endswith(".tar.gz")

    @staticmethod
    def ensure_directory(path):
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def generate_vt_url(sha256_hash):
        if AUTOMATION_CONFIG['VT_LOOKUP_ENABLED']:
            return f"https://www.virustotal.com/gui/file/{sha256_hash}"
        return "N/A"

# ======================= Selenium 옵션 설정 =======================
def create_webdriver_options():
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--blink-settings=imagesEnabled=false")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-plugins")
    options.add_argument("--log-level=3")
    options.add_argument("--disable-webgl")
    options.add_argument("--use-gl=swiftshader")
    options.add_argument("--disable-3d-apis")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36"
    )
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    return options

# ======================= 파일 유틸리티 클래스 =======================
class FileUtils:
    @staticmethod
    def calculate_sha256(path):
        hash_obj = hashlib.sha256()
        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(8192), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    @staticmethod
    def get_file_extension(filename):
        if filename.lower().endswith(".tar.gz"):
            return ".tar.gz"
        ext = os.path.splitext(filename)[1]
        return ext.lower() if ext else "N/A"

    @staticmethod
    def is_tar_gz(filename):
        return filename.lower().endswith(".tar.gz")

    @staticmethod
    def ensure_directory(path):
        os.makedirs(path, exist_ok=True)

    @staticmethod
    def generate_vt_url(sha256_hash):
        if AUTOMATION_CONFIG['VT_LOOKUP_ENABLED']:
            return f"https://www.virustotal.com/gui/file/{sha256_hash}"
        return "N/A"
# ======================= 게시글 URL 수집 =======================
def collect_post_urls(driver):
    post_urls = []
    config = CRAWLER_CONFIG

    logger.info(f"게시글 URL 수집 시작 (최대 {config['MAX_PAGES']} 페이지)")

    for page in range(1, config['MAX_PAGES'] + 1):
        url = config['MAIN_URL'] if page == 1 else f"{config['MAIN_URL']}/?page={page}"
        try:
            logger.info(f"[페이지 {page}] 로딩 중: {url}")
            driver.get(url)

            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "h3.title a, .content"))
            )

            anchors = driver.find_elements(By.CSS_SELECTOR, "h3.title a")
            page_urls = []

            for anchor in anchors:
                href = anchor.get_attribute("href") or ''
                if href.startswith(f"{config['DOMAIN']}/windows/download-"):
                    page_urls.append(href)

            logger.info(f"페이지 {page}에서 {len(page_urls)}개 URL 발견")
            post_urls.extend(page_urls)

        except TimeoutException:
            logger.warning(f"페이지 {page} 로딩 시간 초과")
        except WebDriverException as e:
            logger.warning(f"페이지 {page} 오류: {e}")

    unique_urls = list(dict.fromkeys(post_urls))

    with open(config['URLS_FILE'], 'w', encoding='utf-8') as f:
        json.dump(unique_urls, f, ensure_ascii=False, indent=2)

    logger.info(f"총 {len(unique_urls)}개 게시글 URL 수집 완료")
    return unique_urls

# ======================= 다운로드 링크 수집 =======================
def collect_download_links(driver):
    try:
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'a[href*=".exe"], a[href*=".zip"], a[href*=".rar"], a#various'))
        )
    except TimeoutException:
        logger.warning("다운로드 링크 대기 시간 초과")

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
        matches = re.findall(r'(https?://[^"\s]+?\.(?:exe|zip|rar|msi|7z|tar\.gz)(?:\?[^"\s]*)?)', driver.page_source)
        links = list(dict.fromkeys(matches))

    logger.info(f"{len(links)}개의 다운로드 링크 발견")
    return links
# ======================= 파일 다운로드 (1GB 초과 시 SKIP) =======================
def download_file(session, link, download_dir):
    try:
        logger.info(f"파일 용량 확인 중 (HEAD 요청): {link}")
        head_resp = session.head(link, timeout=15, allow_redirects=True)
        content_length = head_resp.headers.get('Content-Length')

        if content_length:
            file_size_bytes = int(content_length)
            file_size_mb = file_size_bytes / (1024 * 1024)
            if file_size_mb > 1024:
                logger.warning(f"[SKIP] 파일 크기 {file_size_mb:.2f} MB - 1GB 초과")
                return {
                    'url': link,
                    'filename': 'SKIPPED',
                    'sha256': 'SKIPPED',
                    'extension': 'SKIPPED',
                    'size': file_size_bytes,
                    'path': None,
                    'error': f'File too large ({file_size_mb:.2f} MB)'
                }

        logger.info(f"다운로드 시도: {link}")
        response = session.get(link, timeout=60, stream=True)
        response.raise_for_status()

        cd = response.headers.get('content-disposition', '')
        match = re.search(r'filename="?([^";]+)"?', cd)

        if match:
            fname = match.group(1)
        else:
            path = requests.utils.urlparse(response.url).path
            fname = os.path.basename(path)

        root, ext = os.path.splitext(fname)
        if not ext:
            ctype = response.headers.get('Content-Type', '').split(';')[0]
            ext = mimetypes.guess_extension(ctype) or ''
            fname = root + ext

        full_path = os.path.join(download_dir, fname)
        with open(full_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        file_size = os.path.getsize(full_path)
        file_hash = FileUtils.calculate_sha256(full_path)
        file_ext = FileUtils.get_file_extension(fname)

        logger.info(f"다운로드 완료: {fname} ({file_size / 1024:.1f} KB)")

        return {
            'url': link,
            'filename': fname,
            'sha256': file_hash,
            'extension': file_ext,
            'size': file_size,
            'path': full_path
        }

    except Exception as e:
        logger.error(f"다운로드 실패: {link} -> {e}")
        return {
            'url': link,
            'filename': 'N/A',
            'sha256': 'N/A',
            'extension': 'N/A',
            'size': 0,
            'path': None,
            'error': str(e)
        }

# ======================= 작성자 ID 추출 =======================
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
# ======================= 게시글 처리 및 자동 분석 =======================
def process_post(post_url, driver, session):
    try:
        logger.info(f"게시글 처리 시작: {post_url}")
        driver.get(post_url)

        title = WebDriverWait(driver, 15).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, 'h1.text-big span.sw-name'))
        ).text.strip()
        logger.info(f"처리 중: {title}")

        author_id = extract_author_id(driver)

        # 중간 다운로드 버튼 클릭
        dl_button = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, 'a.box-down-bottom'))
        )
        intermediate_url = dl_button.get_attribute('href')
        driver.get(intermediate_url)

        # 광고 스킵 시도
        try:
            skip_selectors = '.ad_skip, .skip-btn, #skip-ad, button.skip-ad, .close-btn'
            skip_ad = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, skip_selectors))
            )
            skip_ad.click()
            time.sleep(2)
        except Exception as e:
            logger.warning(f"광고 스킵 실패 (무시 가능): {e}")

        # 1. 다운로드 링크 수집
        links = collect_download_links(driver)
        if not links:
            raise ValueError("다운로드 링크 없음")

        # 2. 다운로드 디렉토리 확인
        FileUtils.ensure_directory(CRAWLER_CONFIG['DOWNLOAD_DIR'])

        # 3. 압축 비밀번호 추출
        try:
            password = driver.find_element(By.CSS_SELECTOR, 'span#password_rar').text.strip()
        except NoSuchElementException:
            password = 'taiwebs.com'

        # 4. 압축 분석기 준비
        processor = ArchiveProcessor(AUTOMATION_CONFIG)

        # 5. 다운로드 및 처리
        files_info = []
        for link in links:
            file_data = download_file(session, link, CRAWLER_CONFIG['DOWNLOAD_DIR'])
            if not file_data.get("path"):
                continue

            wrapped = {
                "password": password,
                "files": [file_data]
            }

            result_with_extraction = processor.process_file(wrapped)

            file_data['extracted_files'] = result_with_extraction.get('files', [])[0].get('extracted_files', [])
            file_data['extracted_files_total'] = result_with_extraction.get('extracted_files_total', 0)

            files_info.append(file_data)
        # 6. 문서 번호 추출
        match = re.search(r'download-.*-(\d+)\.html$', post_url)
        doc_number = match.group(1) if match else 'N/A'

        # 7. 결과 반환
        return {
            'title': title,
            'author_id': author_id,
            'source_url': intermediate_url,
            'doc_number': doc_number,
            'password': password,
            'files': files_info,
            'collected_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }

    except Exception as error:
        logger.error(f"오류 발생: {post_url} -> {error}")
        return None


# ======================= 압축 처리기 클래스 =======================
class ArchiveProcessor:
    def __init__(self, config):
        self.config = config
        FileUtils.ensure_directory(config['EXTRACT_DIR'])

    def extract_archive(self, filepath, password, depth):
        extracted_files = []
        filename = os.path.basename(filepath)

        # ✅ 파일 존재 여부 확인
        if not os.path.exists(filepath):
            logger.error(f"[압축 파일 없음] 파일 경로가 존재하지 않음: {filepath}")
            return [], "file_not_found"

        is_tar_gz = FileUtils.is_tar_gz(filename)
        extension = ".tar.gz" if is_tar_gz else Path(filepath).suffix.lower()

        inner_dir = os.path.join(
            self.config['EXTRACT_DIR'],
            f"{Path(filepath).stem}_depth{depth}"
        )
        FileUtils.ensure_directory(inner_dir)

        logger.info(f"압축 해제 시작: {filename}, depth={depth}")

        try:
            if extension == '.zip':
                try:
                    with ZipFile(filepath) as zf:
                        zf.extractall(
                            path=inner_dir,
                            pwd=password.encode() if password != 'N/A' else None
                        )
                except Exception as e:
                    logger.warning(f"ZipFile 기본 해제 실패: {e} → 7z 폴백 시도")
                    raise e
            elif extension == '.rar':
                with rarfile.RarFile(filepath) as rf:
                    rf.extractall(
                        path=inner_dir,
                        pwd=password if password != 'N/A' else None
                    )
            elif extension == '.7z':
                with py7zr.SevenZipFile(filepath, mode='r', password=password if password != 'N/A' else None) as sz:
                    sz.extractall(path=inner_dir)
            elif extension == '.tar.gz' or is_tar_gz:
                with tarfile.open(filepath, mode='r:gz') as tf:
                    for member in tf.getmembers():
                        if member.name.startswith('/') or '..' in member.name:
                            logger.warning(f"잠재적 경로 탐색 공격 시도 무시: {member.name}")
                            continue
                        tf.extract(member, path=inner_dir)
            else:
                logger.warning(f"지원하지 않는 압축 포맷: {extension}")
                return [], "unsupported_format"

            # ✅ 내부 파일 해시 계산
            file_count = 0
            for root, _, files in os.walk(inner_dir):
                for fname in files[:self.config['MAX_INNER_FILES']]:
                    full_path = os.path.join(root, fname)
                    try:
                        sha = FileUtils.calculate_sha256(full_path)
                        file_size = os.path.getsize(full_path)
                        file_ext = FileUtils.get_file_extension(fname)

                        extracted_files.append({
                            "filename": fname,
                            "sha256": sha,
                            "vt_url": FileUtils.generate_vt_url(sha),
                            "depth_level": depth,
                            "size": file_size,
                            "extension": file_ext
                        })
                    except Exception as e:
                        logger.error(f"파일 해시 계산 오류: {full_path} -> {e}")

            logger.info(f"내부 파일 {len(extracted_files)}개 해시 완료 (총 {file_count}개 발견)")
            return extracted_files, None

        except Exception as e:
            logger.warning(f"기본 해제 실패: {e}, 7z 폴백 시도 중...")
            extracted, fallback_err = extract_with_7z(filepath, password, inner_dir, depth)
            return (extracted, None) if extracted else ([], fallback_err or str(e))

        finally:
            if self.config['TEMP_CLEANUP_ON_FAIL']:
                shutil.rmtree(inner_dir, ignore_errors=True)
                logger.info(f"임시 폴더 삭제 완료: {inner_dir}")

    def process_file(self, file_info):
        result = file_info.copy()
        files = result.get('files', [])

        if not files or not isinstance(files, list) or len(files) == 0:
            logger.warning("처리할 파일 없음 - 건너뜀")
            result.update({"error": "no_file_info"})
            return result

        all_extraction_results = []

        for file_entry in files:
            if not file_entry or not isinstance(file_entry, dict):
                continue

            filepath = file_entry.get('path')
            if not filepath or not os.path.exists(filepath):
                logger.warning(f"파일 경로 없음: {filepath}")
                file_entry['extraction_error'] = "file_not_found"
                continue

            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > self.config['MAX_FILE_SIZE_MB']:
                logger.warning(f"파일 크기 초과 ({file_size_mb:.2f}MB): {filepath}")
                file_entry['extraction_error'] = f"file_too_large_{file_size_mb:.2f}MB"
                continue

            extension = FileUtils.get_file_extension(file_entry.get('filename', ''))

            # ✅ 비압축 파일 처리 (압축 대상 아님)
            if extension not in self.config['SUPPORTED_EXTENSIONS']:
                logger.info(f"압축 대상 아님 (확장자: {extension}) - 건너뜀")

                # VT URL, 사이즈, 확장자 추가
                sha256 = file_entry.get('sha256')
                if sha256:
                    file_entry['vt_url'] = FileUtils.generate_vt_url(sha256)
                file_entry['size'] = os.path.getsize(filepath)
                file_entry['extension'] = extension

                # 비압축 파일 삭제
                if self.config['REMOVE_AFTER_SCAN'] and os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        logger.info(f"(비압축) 파일 삭제 완료: {filepath}")
                    except Exception as e:
                        logger.error(f"(비압축) 파일 삭제 실패: {filepath} -> {e}")

                continue  # 다음 파일로

            password = result.get('password', 'N/A')
            extraction_results = []

            for depth in range(1, self.config['UNZIP_DEPTH'] + 1):
                extracted_files, err = self.extract_archive(filepath, password, depth)
                if err:
                    file_entry['extraction_error'] = err
                    logger.warning(f"압축 해제 실패 (depth {depth}): {err}")
                    break

                extraction_results.extend(extracted_files)

            file_entry['extracted_files'] = extraction_results
            all_extraction_results.extend(extraction_results)

            if self.config['REMOVE_AFTER_SCAN'] and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    logger.info(f"임시 파일 삭제 완료: {filepath}")
                except Exception as e:
                    logger.error(f"파일 삭제 실패: {filepath} -> {e}")

        result['extracted_files_total'] = len(all_extraction_results)
        return result


    
def extract_with_7z(zip_path, password, output_dir, depth=1):
    """7z.exe CLI를 호출하여 압축을 해제하는 폴백 메서드"""
    try:
        FileUtils.ensure_directory(output_dir)

        cmd = [
            "7z", "x", zip_path,
            f"-o{output_dir}",
            f"-p{password}" if password != 'N/A' else "-p",  # 빈 비번 허용
            "-y"  # 모든 질문 자동 'Yes'
        ]
        logger.info(f"[7z 호출] {' '.join(cmd)}")

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            logger.warning(f"7z 압축 해제 실패: {result.stderr.strip()}")
            return [], result.stderr.strip()

        logger.info("7z 압축 해제 성공")
        return scan_extracted_files(output_dir, depth), None

    except Exception as e:
        logger.error(f"7z 폴백 해제 중 예외: {e}")
        return [], str(e)


def scan_extracted_files(directory, depth_level):
    """추출된 디렉토리 내 모든 파일을 스캔하여 메타데이터 수집"""
    extracted = []
    for root, _, files in os.walk(directory):
        for fname in files:
            full_path = os.path.join(root, fname)
            try:
                sha = FileUtils.calculate_sha256(full_path)
                size = os.path.getsize(full_path)
                ext = FileUtils.get_file_extension(fname)
                extracted.append({
                    "filename": fname,
                    "sha256": sha,
                    "vt_url": FileUtils.generate_vt_url(sha),
                    "size": size,
                    "extension": ext,
                    "depth_level": depth_level  # ⬅ 전달값 사용
                })
            except Exception as e:
                logger.warning(f"7z 파일 스캔 실패: {full_path} -> {e}")
    return extracted




# ======================= JSON 저장/불러오기 유틸리티 =======================
class JsonHandler:
    @staticmethod
    def save_result(data, output_file, append=False):
        try:
            if append and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r', encoding='utf-8') as f:
                    try:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            existing_data = [existing_data]
                    except json.JSONDecodeError:
                        logger.warning(f"손상된 JSON 파일: {output_file}, 새로 시작")
                        existing_data = []

                if isinstance(data, list):
                    existing_data.extend(data)
                else:
                    existing_data.append(data)

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(existing_data, f, ensure_ascii=False, indent=2)
            else:
                with open(output_file, 'w', encoding='utf-8') as f:
                    if isinstance(data, list):
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    else:
                        json.dump([data], f, ensure_ascii=False, indent=2)

            logger.info(f"결과 저장 완료: {output_file}")
            return True

        except Exception as e:
            logger.error(f"결과 저장 실패: {e}")
            return False

    @staticmethod
    def load_data(input_file):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"데이터 로드 실패: {input_file} -> {e}")
            return []
# ======================= 크롤링 메인 실행 함수 =======================
def run_crawler():
    logger.info("크롤러 시작")
    FileUtils.ensure_directory(CRAWLER_CONFIG['DOWNLOAD_DIR'])

    driver = webdriver.Chrome(options=create_webdriver_options())
    driver.implicitly_wait(10)
    driver.set_page_load_timeout(60)
    session = create_session()

    try:
        post_urls = collect_post_urls(driver)

        # 결과 저장 파일 초기화
        with open(CRAWLER_CONFIG['OUTPUT_FILE'], 'w', encoding='utf-8') as f:
            json.dump([], f)

        count = 0  # 처리 개수 카운트

        for idx, url in enumerate(post_urls):
            logger.info(f"[{idx+1}/{len(post_urls)}] 게시글 처리 중: {url}")
            try:
                data = process_post(url, driver, session)
                if data:
                    JsonHandler.save_result([data], CRAWLER_CONFIG['OUTPUT_FILE'], append=True)
                    count += 1
            except Exception as e:
                logger.error(f"게시글 처리 실패: {url} -> {e}")
                continue

        logger.info(f"크롤링 완료: 총 {count}/{len(post_urls)}개 게시글 처리 성공")
        return True

    except Exception as e:
        logger.error(f"크롤러 실행 오류: {e}")
        return False

    finally:
        driver.quit()
        logger.info("WebDriver 종료")

# ======================= 메인 실행 =======================
if __name__ == "__main__":
    try:
        # 작업 디렉토리 확인
        for dir_path in [CRAWLER_CONFIG['DOWNLOAD_DIR'], AUTOMATION_CONFIG['EXTRACT_DIR']]:
            FileUtils.ensure_directory(dir_path)

        # 크롤러 실행
        logger.info("===== 크롤러 실행 시작 =====")
        crawl_success = run_crawler()

        if not crawl_success:
            logger.error("크롤러 실행 실패")
        else:
            logger.info("크롤러 실행 성공")

        # 최종 결과 요약
        logger.info("===== 작업 완료 =====")
        logger.info(f"크롤러 결과: {'성공' if crawl_success else '실패'}")

        # 설정 기반 디렉토리 정리 (옵션)
        if AUTOMATION_CONFIG.get('CLEANUP_ALL_AFTER_PROCESS', False):
            try:
                if os.path.exists(CRAWLER_CONFIG['DOWNLOAD_DIR']):
                    shutil.rmtree(CRAWLER_CONFIG['DOWNLOAD_DIR'], ignore_errors=True)
                    logger.info(f"다운로드 디렉토리 삭제: {CRAWLER_CONFIG['DOWNLOAD_DIR']}")

                if os.path.exists(AUTOMATION_CONFIG['EXTRACT_DIR']):
                    shutil.rmtree(AUTOMATION_CONFIG['EXTRACT_DIR'], ignore_errors=True)
                    logger.info(f"압축 해제 디렉토리 삭제: {AUTOMATION_CONFIG['EXTRACT_DIR']}")

                FileUtils.ensure_directory(CRAWLER_CONFIG['DOWNLOAD_DIR'])
                FileUtils.ensure_directory(AUTOMATION_CONFIG['EXTRACT_DIR'])
                logger.info("디렉토리 재생성 완료")

            except Exception as e:
                logger.error(f"최종 정리 중 오류: {e}")

    except Exception as e:
        logger.critical(f"프로그램 실행 중 치명적 오류 발생: {e}")

    finally:
        logger.info("프로그램 종료")
