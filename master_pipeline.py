import os
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime

# --- КОНФИГУРАЦИЯ И СЛОВАРЕЙ ПРАВИЛ ---

EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

BLACKLIST_DIRS = {
    "Templates",     # Макеты
    "Forms",         # Формы
    "Ext",           # Внутренние структуры
    "Tests",         # Тесты
    "Pictures"       # Картинки
}

WHITELIST_FILENAMES = {
    "ObjectModule.bsl",
    "ManagerModule.bsl",
    "RecordSetModule.bsl",
    "ValueModule.bsl",
    "Module.bsl"
}

def load_targets(file_path=None):
    """Загружает список целевых ключей/логинов из файла или возвращает дефолтный набор."""
    targets = set()
    if file_path and Path(file_path).exists():
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    targets.add(clean.lower())
    if not targets:
        targets = {"пароль", "password", "pwd", "логин", "login", "user", "token", "токен", "secret"}
    return targets

def get_safe_replacement(keyword):
    """Генерирует безопасный вызов БСП."""
    kw_lower = keyword.lower()
    if any(k in kw_lower for k in ["пароль", "password", "pwd", "secret"]):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Пароль"
    elif any(k in kw_lower for k in ["логин", "user", "login"]):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Логин"
    else:
        return f"ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().{keyword.capitalize()}"

def should_skip_path(file_path, root_path):
    try:
        rel_parts = Path(file_path).relative_to(root_path).parts
        for part in rel_parts:
            if part in BLACKLIST_DIRS:
                return True
    except ValueError:
        pass
    return False

def run_v8unpack(args, timeout=30):
    """Вспомогательная функция вызова v8unpack с обработкой ошибок."""
    try:
        res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return res.returncode == 0, res.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Тайм-аут выполнения v8unpack"
    except Exception as e:
        return False, str(e)

def process_pipeline(source_epf_dir, target_epf_dir, work_dir, targets_file=None, v8unpack_cmd="v8unpack"):
    src_path = Path(source_epf_dir)
    tgt_path = Path(target_epf_dir)
    wrk_path = Path(work_dir)
    
    tgt_path.mkdir(parents=True, exist_ok=True)
    wrk_path.mkdir(parents=True, exist_ok=True)
    
    targets = load_targets(targets_file)
    pattern_str = r"(?i)\b(" + "|".join(re.escape(t) for t in targets) + r")\b\s*=\s*\"([^\"]+)\""
    cred_regex = re.compile(pattern_str)
    
    epf_files = list(src_path.rglob("*.epf")) + list(src_path.rglob("*.erf"))
    total = len(epf_files)
    
    print(f"[*] Старт единого пайплайна обработки обработок 1С.")
    print(f"[*] Найдено файлов для обработки: {total}")
    print("=" * 70)
    
    stats = {
        "unpacked_success": 0,
        "unpacked_fail": 0,
        "files_modified": 0,
        "total_replacements": 0,
        "packed_success": 0,
        "packed_fail": 0
    }
    
    audit_log = []
    
    for idx, epf_path in enumerate(epf_files, 1):
        print(f"\n[{idx}/{total}] Обработка файла: {epf_path.name}")
        
        # Шаг 1: Распаковка
        extracted_folder = wrk_path / epf_path.stem
        if extracted_folder.exists():
            shutil.rmtree(extracted_folder, ignore_errors=True)
        extracted_folder.mkdir(parents=True, exist_ok=True)
        
        success, err = run_v8unpack([v8unpack_cmd, "-unpack", str(epf_path), str(extracted_folder)])
        if not success:
            print(f"  [!] Ошибка распаковки: {err}")
            stats["unpacked_fail"] += 1
            continue
        stats["unpacked_success"] += 1
        
        # Шаг 2: Рефакторинг (поиск и замена в .bsl модулях)
        file_replacements = 0
        for bsl_file in extracted_folder.rglob("*.bsl"):
            if bsl_file.name not in WHITELIST_FILENAMES:
                continue
            if should_skip_path(bsl_file, extracted_folder):
                continue
                
            try:
                with open(bsl_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                    content = f.read()
                
                def replace_match(match):
                    nonlocal file_replacements
                    keyword = match.group(1)
                    secret_val = match.group(2).strip().lower()
                    
                    if secret_val and secret_val not in EXCLUDED_VALUES:
                        file_replacements += 1
                        stats["total_replacements"] += 1
                        safe_expr = get_safe_replacement(keyword)
                        full_match = match.group(0)
                        indent_match = re.match(r"^(\s*)", full_match)
                        indent = indent_match.group(1) if indent_match else ""
                        
                        audit_log.append({
                            "epf": epf_path.name,
                            "module": bsl_file.name,
                            "match": full_match,
                            "replacement": f"{indent}{keyword} = {safe_expr};"
                        })
                        return f"{indent}{keyword} = {safe_expr};"
                    return match.group(0)

                new_content = cred_regex.sub(replace_match, content)
                if file_replacements > 0:
                    with open(bsl_file, "w", encoding="utf-8-sig") as f:
                        f.write(new_content)
            except Exception as ex:
                print(f"  [!] Ошибка модификации модуля {bsl_file.name}: {ex}")
                
        if file_replacements > 0:
            stats["files_modified"] += 1
            print(f"  [FIX] Найдено и заменено секретов в модулях: {file_replacements}")
        else:
            print(f"  [OK] Укгроз не обнаружено.")

        # Шаг 3: Обратная упаковка в EPF/ERF
        output_epf_file = tgt_path / epf_path.name
        success_pack, err_pack = run_v8unpack([v8unpack_cmd, "-pack", str(extracted_folder), str(output_epf_file)])
        
        if success_pack:
            stats["packed_success"] += 1
            print(f"  [OK] Успешно запаковано обратно -> {output_epf_file.name}")
        else:
            stats["packed_fail"] += 1
            print(f"  [!] Ошибка обратной упаковки: {err_pack}")

    # Сохранение итогового отчета
    report_path = tgt_path / f"pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w", encoding="utf-8") as rep:
        rep.write("=== СВОДНЫЙ ОТЧЕТ ПАЙПЛАЙНА АУДИТА И РЕФАКТОРИНГА EPF ===\n\n")
        rep.write(f"Всего файлов обработано: {total}\n")
        rep.write(f"Успешно распаковано: {stats['unpacked_success']}\n")
        rep.write(f"Ошибок распаковки: {stats['unpacked_fail']}\n")
        rep.write(f"Модифицировано файлов: {stats['files_modified']}\n")
        rep.write(f"Всего заменено уязвимостей: {stats['total_replacements']}\n")
        rep.write(f"Успешно упаковано обратно: {stats['packed_success']}\n")
        rep.write(f"Ошибок упаковки: {stats['packed_fail']}\n\n")
        rep.write("--- ДЕТАЛИЗАЦИЯ ИСПРАВЛЕНИЙ ---\n")
        for item in audit_log:
            rep.write(f"Файл: {item['epf']} | Модуль: {item['module']}\n")
            rep.write(f"  Было:  {item['match']}\n")
            rep.write(f"  Стало: {item['replacement']}\n")
            rep.write("-" * 40 + "\n")
            
    print("=" * 70)
    print(f"[*] Пайплайн завершен.")
    print(f"    Итоговый отчет сохранен в: {report_path.absolute()}")

if __name__ == "__main__":
    src_dir = input("Путь к исходной папке с файлами .epf/.erf: ").strip().strip('"\'')
    tgt_dir = input("Путь для сохранения обработанных .epf/.erf: ").strip().strip('"\'')
    wrk_dir = input("Путь для временной распаковки (например, C:\\Temp\\EpfsWork): ").strip().strip('"\'')
    
    t_file = input("Путь к файлу со списком учетных записей/ключей (Enter для стандартных): ").strip().strip('"\'')
    t_file = t_file if t_file else None
    
    if os.path.isdir(src_dir):
        process_pipeline(src_dir, tgt_dir, wrk_dir, targets_file=t_file)
    else:
        print("[!] Ошибка: Указанная исходная директория не существует.")