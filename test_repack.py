import os
import subprocess
import shutil
import re
from pathlib import Path

# Ключевые слова для поиска уязвимостей
KEYWORDS = [
    r"пароль", r"password", r"pwd",
    r"логин", r"login", r"user", r"пользователь",
    r"token", r"токен", r"secret", r"api[_-]?key"
]

CRED_REGEX = re.compile(r"(?i)\b(" + "|".join(KEYWORDS) + r")\b\s*=\s*\"([^\"]+)\"")
EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

def unpack_epf(epf_path, temp_output_dir, v8unpack_cmd="v8unpack"):
    """Распаковывает отдельный файл .epf / .erf во временную подпапку."""
    epf_p = Path(epf_path)
    target_dir = Path(temp_output_dir) / epf_p.stem
    target_dir.mkdir(parents=True, exist_ok=True)
    
    cmd = [v8unpack_cmd, "-unpack", str(epf_p), str(target_dir)]
    try:
        # Запускаем распаковку с таймаутом в 30 секунд на случай зависания на битых файлах
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if result.returncode == 0:
            return target_dir
        else:
            print(f"[!] Ошибка распаковки {epf_p.name}: {result.stderr.strip()}")
            return None
    except subprocess.TimeoutExpired:
        print(f"[!] Тайм-аут при распаковке файла {epf_p.name}")
        return None
    except Exception as e:
        print(f"[!] Сбой вызова v8unpack для {epf_p.name}: {e}")
        return None

def scan_extracted_files(extracted_dir, epf_name):
    """Рекурсивно сканирует все распакованные файлы внутренней структуры EPF на наличие секретов."""
    found_issues = []
    extracted_path = Path(extracted_dir)
    
    for file_path in extracted_path.rglob("*"):
        if file_path.is_file():
            try:
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    lines = f.readlines()
                    
                for line_idx, line in enumerate(lines, 1):
                    match = CRED_REGEX.search(line)
                    if match:
                        keyword, secret_val = match.groups()
                        cleaned_val = secret_val.strip().lower()
                        
                        if cleaned_val and cleaned_val not in EXCLUDED_VALUES:
                            found_issues.append({
                                "epf": epf_name,
                                "internal_file": file_path.name,
                                "line": line_idx,
                                "keyword": keyword,
                                "value": secret_val,
                                "code_snippet": line.strip()
                            })
            except Exception:
                # Пропускаем бинарные файлы или файлы, которые не удается прочитать как текст
                pass
                
    return found_issues

def process_all_exts(source_dir, work_dir, v8unpack_cmd="v8unpack"):
    source_path = Path(source_dir)
    work_path = Path(work_dir)
    work_path.mkdir(parents=True, exist_ok=True)
    
    epf_files = list(source_path.rglob("*.epf")) + list(source_path.rglob("*.erf"))
    total_files = len(epf_files)
    
    print(f"[*] Найдено файлов обработок и отчетов для анализа: {total_files}")
    print("-" * 70)
    
    all_findings = []
    success_count = 0
    fail_count = 0
    
    for idx, epf_path in enumerate(epf_files, 1):
        print(f"[{idx}/{total_files}] Обработка: {epf_path.name}")
        
        # Шаг 1. Распаковка EPF
        unpacked_dir = unpack_epf(epf_path, work_path, v8unpack_cmd)
        if unpacked_dir:
            success_count += 1
            # Шаг 2. Сканирование содержимого
            issues = scan_extracted_files(unpacked_dir, epf_path.name)
            if issues:
                print(f"  [!] Найдено потенциальных секретов: {len(issues)}")
                all_findings.extend(issues)
                for issue in issues:
                    print(f"      -> Файл: {issue['internal_file']}, Стр. {issue['line']}: '{issue['keyword']}' = '{issue['value']}'")
        else:
            fail_count += 1
            
    print("-" * 70)
    print(f"[*] Обработка завершена.")
    print(f"    Успешно распаковано: {success_count}, Ошибок распаковки: {fail_count}")
    print(f"    Всего обнаружено подозрительных вхождений: {len(all_findings)}")
    
    # Сохранение итогового отчета в файл
    report_path = work_path / "security_audit_report.txt"
    with open(report_path, "w", encoding="utf-8") as rep:
        rep.write(f"Отчет аудита безопасности внешних обработок\n")
        rep.write(f"=" * 50 + "\n\n")
        for item in all_findings:
            rep.write(f"Обработка: {item['epf']}\n")
            rep.write(f"Внутренний файл: {item['internal_file']} (строка {item['line']})\n")
            rep.write(f"Ключ: {item['keyword']} | Значение: {item['value']}\n")
            rep.write(f"Строка кода: {item['code_snippet']}\n")
            rep.write("-" * 40 + "\n")
    print(f"[*] Подробный отчет сохранен в: {report_path.absolute()}")

if __name__ == "__main__":
    src_dir = input("Введите путь к папке с выгруженными файлами .epf/.erf: ").strip().strip('"\'')
    tmp_dir = input("Введите путь для временной распаковки (например, C:\Temp\EpfsUnpacked): ").strip().strip('"\'')
    
    if os.path.isdir(src_dir):
        process_all_exts(src_dir, tmp_dir)
    else:
        print("[!] Ошибка: Указанный путь исходной директории не существует.")