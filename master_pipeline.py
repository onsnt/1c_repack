import os
import subprocess
import shutil
import re
from pathlib import Path
from datetime import datetime

# --- ПРАВИЛА И ФИЛЬТРЫ ---

EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

BLACKLIST_DIRS = {
    "Templates", "Forms", "Ext", "Tests", "Pictures", "Bin"
}

WHITELIST_FILENAMES = {
    "ObjectModule.bsl",
    "ManagerModule.bsl",
    "RecordSetModule.bsl",
    "ValueModule.bsl",
    "Module.bsl"
}

def load_targets(file_path):
    targets = set()
    path = Path(file_path) if file_path else None
    
    if path and path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        targets.add(clean.lower())
            print(f"[*] Загружено целей из файла '{path.name}': {len(targets)} шт.")
        except Exception as e:
            print(f"[!] Ошибка чтения файла целей: {e}")
            
    if not targets:
        targets = {"пароль", "password", "pwd", "логин", "login", "user", "token", "токен", "secret"}
        print("[*] Используются дефолтные ключевые слова.")
        
    return targets

def get_safe_replacement(keyword):
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
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", timeout=timeout)
        if res.returncode == 0:
            return True, ""
        else:
            return False, res.stderr.strip() or res.stdout.strip()
    except Exception as e:
        return False, str(e)

def process_bsl_directory(root_dir, cred_regex, audit_log, container_name=""):
    """Сканирует и правит .bsl файлы внутри указанного каталога."""
    root_path = Path(root_dir)
    modified_count = 0
    replacements_count = 0
    
    for bsl_file in root_path.rglob("*.bsl"):
        if bsl_file.name not in WHITELIST_FILENAMES:
            continue
        if should_skip_path(bsl_file, root_path):
            continue
            
        try:
            # Читаем с защитой от кодировок (UTF-8 с BOM, UTF-8, ANSI)
            content = None
            for enc in ["utf-8-sig", "utf-8", "cp1251"]:
                try:
                    with open(bsl_file, "r", encoding=enc) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                continue

            file_mutated = False
            
            def replace_match(match):
                nonlocal replacements_count, file_mutated
                keyword = match.group(1)
                secret_val = match.group(2).strip()
                
                # Проверяем реальное наличие значения (не пустое и не заглушка)
                if secret_val and secret_val.lower() not in EXCLUDED_VALUES:
                    file_mutated = True
                    replacements_count += 1
                    safe_expr = get_safe_replacement(keyword)
                    full_match = match.group(0)
                    indent_match = re.match(r"^(\s*)", full_match)
                    indent = indent_match.group(1) if indent_match else ""
                    
                    audit_log.append({
                        "container": container_name or root_path.name,
                        "module": str(bsl_file.relative_to(root_path)),
                        "match": full_match,
                        "replacement": f"{indent}{keyword} = {safe_expr};"
                    })
                    return f"{indent}{keyword} = {safe_expr};"
                return match.group(0)

            new_content = cred_regex.sub(replace_match, content)
            
            if file_mutated:
                modified_count += 1
                with open(bsl_file, "w", encoding="utf-8-sig") as f:
                    f.write(new_content)
                print(f"  [FIX] Исправлен модуль: {bsl_file.relative_to(root_path)}")
                
        except Exception as ex:
            print(f"  [!] Ошибка обработки файла {bsl_file.name}: {ex}")
            
    return modified_count, replacements_count

def run_pipeline():
    print("=" * 60)
    print(" АУДИТ И РЕФАКТОРИНГ СЕКРЕТОВ В КОДЕ 1С (УПП 1.3 / EPF)")
    print("=" * 60)
    
    print("\nВыберите режим работы:")
    print("  1. Режим конфигурации (каталог исходников XML / EDT структуры)")
    print("  2. Режим внешних обработок / отчетов (.epf / .erf контейнеры)")
    
    mode = input("Введите номер режима (1 или 2): ").strip()
    
    src_input = input("Путь к исходному каталогу с файлами/структурой: ").strip().strip('"\'')
    tgt_input = input("Путь для сохранения результатов: ").strip().strip('"\'')
    t_txt_input = input("Путь к файлу со списком логинов/ключей (Enter для дефолтных): ").strip().strip('"\'')
    
    src_path = Path(src_input).resolve()
    tgt_path = Path(tgt_input).resolve()
    targets = load_targets(t_txt_input if t_txt_input else None)
    
    # Гибкое регулярное выражение для поиска ключевое_слово = "значение"
    pattern_str = r"(?i)\b(" + "|".join(re.escape(t) for t in targets) + r")\b\s*=\s*\"([^\"]*)\""
    cred_regex = re.compile(pattern_str)
    
    audit_log = []
    
    if mode == "1":
        # РЕЖИМ 1: Работа с каталогом конфигурации (XML / EDT) напрямую
        print(f"\n[*] Запуск аудита структуры конфигурации в каталоге: {src_path}")
        if not src_path.is_dir():
            print(f"[!] Каталог не найден: {src_path}")
            return
            
        # Копируем структуру в целевую папку, чтобы не портить оригинал
        if tgt_path != src_path:
            if tgt_path.exists():
                shutil.rmtree(tgt_path)
            shutil.copytree(src_path, tgt_path)
            work_target = tgt_path
        else:
            work_target = src_path
            
        mod_files, total_rep = process_bsl_directory(work_target, cred_regex, audit_log, container_name="Configuration_XML")
        print(f"\n[*] Аудит конфигурации завершен. Изменено модулей: {mod_files}, заменено секретов: {total_rep}")
        
    elif mode == "2":
        # РЕЖИМ 2: Пакетная обработка контейнеров .epf / .erf / .cf
        wrk_input = input("Путь к временной рабочей папке для распаковки: ").strip().strip('"\'')
        wrk_path = Path(wrk_input).resolve()
        
        skip_unpack_input = input("Пропустить этап распаковки и анализировать готовые папки? (y/N): ").strip().lower()
        skip_unpack = (skip_unpack_input == 'y')
        
        tgt_path.mkdir(parents=True, exist_ok=True)
        wrk_path.mkdir(parents=True, exist_ok=True)
        
        total_replacements = 0
        processed_count = 0
        
        if skip_unpack:
            print(f"\n[*] РЕЖИМ БЕЗ РАСПАКОВКИ: Сканируем готовые папки в {wrk_path}")
            folders = [f for f in wrk_path.iterdir() if f.is_dir()]
            for folder in folders:
                print(f"\n[Анализ папки] {folder.name}")
                _, reps = process_bsl_directory(folder, cred_regex, audit_log, container_name=folder.name)
                total_replacements += reps
                processed_count += 1
                # В режиме без распаковки упаковка обратно НЕ выполняется
        else:
            containers = list(src_path.rglob("*.epf")) + list(src_path.rglob("*.erf")) + list(src_path.rglob("*.cf"))
            print(f"\n[*] Найдено контейнеров для пайплайна: {len(containers)}")
            
            for idx, file_p in enumerate(containers, 1):
                print(f"\n[{idx}/{len(containers)}] Обработка: {file_p.name}")
                extracted_dir = wrk_path / file_p.stem
                if extracted_dir.exists():
                    shutil.rmtree(extracted_dir, ignore_errors=True)
                extracted_dir.mkdir(parents=True, exist_ok=True)
                
                # Распаковка
                success, err = run_v8unpack_saby("-u", file_p, extracted_dir)
                if not success:
                    print(f"  [!] Ошибка распаковки: {err}")
                    continue
                    
                # Анализ и рефакторинг
                _, reps = process_bsl_directory(extracted_dir, cred_regex, audit_log, container_name=file_p.name)
                total_replacements += reps
                
                # Обратная упаковка
                out_file = tgt_path / file_p.name
                success_pack, err_pack = run_v8unpack_saby("-p", extracted_dir, out_file)
                if success_pack:
                    print(f"  [OK] Запаковано обратно -> {out_file.name}")
                    processed_count += 1
                else:
                    print(f"  [!] Ошибка упаковки: {err_pack}")
                    
        print(f"\n[*] Пайплайн обработок завершен. Обработано контейнеров: {processed_count}, заменено уязвимостей: {total_replacements}")
    else:
        print("[!] Неверный выбор режима.")
        return

    # Генерация отчета
    report_path = tgt_path / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w", encoding="utf-8") as rep:
        rep.write("=== ОТЧЕТ АУДИТА И РЕФАКТОРИНГА 1С ===\n\n")
        rep.write(f"Всего заменено вхождений: {len(audit_log)}\n\n")
        for item in audit_log:
            rep.write(f"Контейнер/Объект: {item['container']} | Модуль: {item['module']}\n")
            rep.write(f"  Было:  {item['match']}\n")
            rep.write(f"  Стало: {item['replacement']}\n")
            rep.write("-" * 40 + "\n")
            
    print(f"[*] Отчет сохранен в: {report_path.absolute()}")

if __name__ == "__main__":
    run_pipeline()