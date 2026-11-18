import os
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime

# --- КОНФИГУРАЦИЯ И ПРАВИЛА ---

EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

# Черный каталог (исключаем формы, макеты и служебные папки)
BLACKLIST_DIRS = {
    "Templates", "Forms", "Ext", "Tests", "Pictures"
}

# Белый список файлов модулей для проверки и рефакторинга
WHITELIST_FILENAMES = {
    "ObjectModule.bsl",
    "ManagerModule.bsl",
    "RecordSetModule.bsl",
    "ValueModule.bsl",
    "Module.bsl"
}

def load_targets(file_path):
    """Корректно загружает список логинов/ключей из текстового файла."""
    targets = set()
    path = Path(file_path) if file_path else None
    
    if path and path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        targets.add(clean.lower())
            print(f"[*] Успешно загружено целей из файла '{path.name}': {len(targets)} шт.")
        except Exception as e:
            print(f"[!] Ошибка чтения файла целей: {e}")
            
    if not targets:
        # Дефолтный набор, если файл не задан или пуст
        targets = {"пароль", "password", "pwd", "логин", "login", "user", "token", "токен", "secret"}
        print("[*] Используются стандартные ключевые слова по умолчанию.")
        
    return targets

def get_safe_replacement(keyword):
    """Генерирует безопасный вызов общего модуля для старых конфигураций (УПП 1.3)."""
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

def run_v8unpack_saby(action, source_path, target_path, timeout=60):
    src = str(Path(source_path).resolve())
    tgt = str(Path(target_path).resolve())
    
    cmd = ["python", "-m", "v8unpack", action, src, tgt]
    
    try:
        res = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            encoding="utf-8", 
            timeout=timeout
        )
        
        # Проверяем, что каталог действительно заполнился файлами, а не остался пустым
        target_p = Path(tgt)
        if res.returncode == 0:
            if action == "-u" and not any(target_p.iterdir()):
                return False, "Утилита отчиталась об успехе, но каталог распаковки остался пустым (неверный формат cf/epf)."
            return True, ""
        else:
            return False, res.stderr.strip() or res.stdout.strip()
            
    except Exception as e:
        return False, str(e)
    
def process_pipeline(source_dir, target_dir, work_dir, targets_file=None):
    src_path = Path(source_dir).resolve()
    tgt_path = Path(target_dir).resolve()
    wrk_path = Path(work_dir).resolve()
    
    tgt_path.mkdir(parents=True, exist_ok=True)
    wrk_path.mkdir(parents=True, exist_ok=True)
    
    # 1. Загрузка целей из файла
    targets = load_targets(targets_file)
    
    # Динамическое формирование безопасного RegExp на базе загруженного списка
    pattern_str = r"(?i)\b(" + "|".join(re.escape(t) for t in targets) + r")\b\s*=\s*\"([^\"]+)\""
    cred_regex = re.compile(pattern_str)
    
    # Ищем файлы .cf, .epf, .erf
    container_files = list(src_path.rglob("*.cf")) + list(src_path.rglob("*.epf")) + list(src_path.rglob("*.erf"))
    total = len(container_files)
    
    print(f"[*] Старт единого пайплайна. Найдено файлов (.cf/.epf/.erf): {total}")
    print("=" * 70)
    
    stats = {"success": 0, "fail": 0, "modified": 0, "replacements": 0, "packed": 0}
    audit_log = []
    
    for idx, file_path in enumerate(container_files, 1):
        print(f"\n[{idx}/{total}] Обработка: {file_path.name}")
        
        extracted_folder = wrk_path / file_path.stem
        if extracted_folder.exists():
            shutil.rmtree(extracted_folder, ignore_errors=True)
        extracted_folder.mkdir(parents=True, exist_ok=True)
        
        # Шаг 2: Распаковка через saby-integration (-u)
        success, err = run_v8unpack_saby("-u", file_path, extracted_folder)
        if not success:
            print(f"  [!] Ошибка распаковки: {err}")
            stats["fail"] += 1
            continue
        stats["success"] += 1
        
        # Шаг 3: Поиск и замена в BSL-модулях
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
                        stats["replacements"] += 1
                        safe_expr = get_safe_replacement(keyword)
                        full_match = match.group(0)
                        indent_match = re.match(r"^(\s*)", full_match)
                        indent = indent_match.group(1) if indent_match else ""
                        
                        audit_log.append({
                            "container": file_path.name,
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
            stats["modified"] += 1
            print(f"  [FIX] Заменено вхождений: {file_replacements}")
        else:
            print(f"  [OK] Угроз не обнаружено.")

        # Шаг 4: Обратная упаковка через saby-integration (-p)
        output_file = tgt_path / file_path.name
        success_pack, err_pack = run_v8unpack_saby("-p", extracted_folder, output_file)
        
        if success_pack:
            stats["packed"] += 1
            print(f"  [OK] Успешно запаковано -> {output_file.name}")
        else:
            print(f"  [!] Ошибка упаковки: {err_pack}")

    # Генерация итогового отчета
    report_path = tgt_path / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w", encoding="utf-8") as rep:
        rep.write("=== ОТЧЕТ ПАЙПЛАЙНА АУДИТА И РЕФАКТОРИНГА 1С ===\n\n")
        rep.write(f"Обработано файлов: {total}\n")
        rep.write(f"Успешно распаковано: {stats['success']}\n")
        rep.write(f"Модифицировано файлов: {stats['modified']}\n")
        rep.write(f"Заменено уязвимостей: {stats['replacements']}\n\n")
        rep.write("--- ДЕТАЛИЗАЦИЯ ИСПРАВЛЕНИЙ ---\n")
        for item in audit_log:
            rep.write(f"Файл: {item['container']} | Модуль: {item['module']}\n")
            rep.write(f"  Было:  {item['match']}\n")
            rep.write(f"  Стало: {item['replacement']}\n")
            rep.write("-" * 40 + "\n")
            
    print("=" * 70)
    print(f"[*] Готово. Отчет сохранен в: {report_path.absolute()}")

if __name__ == "__main__":
    src_input = input("Путь к каталогу с файлами (.cf, .epf, .erf): ").strip().strip('"\'')
    tgt_input = input("Путь для сохранения обработанных файлов: ").strip().strip('"\'')
    wrk_input = input("Путь для временной распаковки (например, C:\\Temp\\Work1C): ").strip().strip('"\'')
    t_txt_input = input("Путь к текстовому файлу со списком логинов/ключей (Enter для дефолтных): ").strip().strip('"\'')
    
    if os.path.isdir(src_input):
        process_pipeline(src_input, tgt_input, wrk_input, targets_file=t_txt_input if t_txt_input else None)
    else:
        print(f"[!] Ошибка: Указанный каталог не найден -> {src_input}")