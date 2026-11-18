import os
import subprocess
import shutil
import re
import hashlib
from pathlib import Path
from datetime import datetime

# --- СИСТЕМНЫЕ КЛЮЧЕВЫЕ СЛОВА (Имена переменных слева от =) ---
SYSTEM_KEYWORDS = {
    "пароль", "password", "pwd", "secret", "token", "токен", "api_key",
    "логин", "login", "user", "пользователь", "имяпользователя"
}

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

def load_user_values(file_path):
    values = set()
    path = Path(file_path) if file_path else None
    
    if path and path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        values.add(clean.lower())
            print(f"[*] Загружено учетных записей из файла '{path.name}': {len(values)} шт.")
        except Exception as e:
            print(f"[!] Ошибка чтения файла значений: {e}")
            
    return values

def get_safe_replacement(var_name, val_str):
    combined = (var_name + " " + val_str).lower()
    if any(k in combined for k in ["пароль", "password", "pwd", "secret", "token", "11"]):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Пароль"
    else:
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Логин"

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

def get_file_hash(file_path):
    """Вычисляет MD5-хэш файла для проверки изменений."""
    hasher = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except Exception:
        return None

def smart_copy_file(src_file, tgt_file):
    """Копирует файл в целевой каталог, только если он изменился (сравнение по MD5)."""
    src_p = Path(src_file)
    tgt_p = Path(tgt_file)
    
    if tgt_p.exists():
        src_hash = get_file_hash(src_p)
        tgt_hash = get_file_hash(tgt_p)
        if src_hash and tgt_hash and src_hash == tgt_hash:
            return False # Файл не изменился, копирование пропущено
            
    tgt_p.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_p, tgt_p)
    return True # Файл скопирован (новый или измененный)

def process_bsl_directory(root_dir, user_values, audit_log, container_name=""):
    root_path = Path(root_dir)
    modified_count = 0
    replacements_count = 0
    assignment_regex = re.compile(r"(?i)\b([a-zA-Zа-яА-Я0-9_]+)\s*=\s*\"([^\"]*)\"")
    
    for bsl_file in root_path.rglob("*.bsl"):
        if bsl_file.name not in WHITELIST_FILENAMES:
            continue
        if should_skip_path(bsl_file, root_path):
            continue
            
        try:
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
                var_name = match.group(1)
                var_val = match.group(2)
                
                val_clean = var_val.strip()
                if not val_clean or val_clean.lower() in EXCLUDED_VALUES:
                    return match.group(0)
                
                is_keyword_match = var_name.lower() in SYSTEM_KEYWORDS
                is_value_match = val_clean.lower() in user_values
                
                if is_keyword_match or is_value_match:
                    file_mutated = True
                    replacements_count += 1
                    safe_expr = get_safe_replacement(var_name, var_val)
                    full_match = match.group(0)
                    indent_match = re.match(r"^(\s*)", full_match)
                    indent = indent_match.group(1) if indent_match else ""
                    
                    audit_log.append({
                        "container": container_name or root_path.name,
                        "module": str(bsl_file.relative_to(root_path)),
                        "match": full_match,
                        "replacement": f"{indent}{var_name} = {safe_expr};"
                    })
                    return f"{indent}{var_name} = {safe_expr};"
                
                return match.group(0)

            new_content = assignment_regex.sub(replace_match, content)
            
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
    tgt_input = input("Путь для сохранения результатов (готовый каталог): ").strip().strip('"\'')
    t_txt_input = input("Путь к файлу со списком логинов/учеток: ").strip().strip('"\'')
    
    src_path = Path(src_input).resolve()
    tgt_path = Path(tgt_input).resolve()
    user_values = load_user_values(t_txt_input)
    
    audit_log = []
    tgt_path.mkdir(parents=True, exist_ok=True)
    
    if mode == "1":
        print(f"\n[*] Аудит структуры конфигурации в каталоге: {src_path}")
        if not src_path.is_dir():
            print(f"[!] Каталог не найден: {src_path}")
            return
            
        # Полная синхронизация структуры конфигурации с умным пропуском неизмененных файлов
        copied_count = 0
        skipped_count = 0
        
        for src_file in src_path.rglob("*"):
            if src_file.is_file():
                rel_p = src_file.relative_to(src_path)
                tgt_file = tgt_path / rel_p
                if smart_copy_file(src_file, tgt_file):
                    copied_count += 1
                else:
                    skipped_count += 1
                    
        print(f"[*] Синхронизация завершена. Скопировано/обновлено файлов: {copied_count}, пропущено (без изменений): {skipped_count}")
        
        # Запускаем рефакторинг прямо в целевом каталоге
        mod_files, total_rep = process_bsl_directory(tgt_path, user_values, audit_log, container_name="Configuration_XML")
        print(f"\n[*] Готово. Изменено модулей: {mod_files}, заменено секретов: {total_rep}")
        
    elif mode == "2":
        wrk_input = input("Путь к временной рабочей папке для распаковки: ").strip().strip('"\'')
        wrk_path = Path(wrk_input).resolve()
        
        skip_unpack_input = input("Пропустить этап распаковки и анализировать готовые папки? (y/N): ").strip().lower()
        skip_unpack = (skip_unpack_input == 'y')
        
        wrk_path.mkdir(parents=True, exist_ok=True)
        
        total_replacements = 0
        processed_count = 0
        copied_containers = 0
        skipped_containers = 0
        
        if skip_unpack:
            print(f"\n[*] РЕЖИМ БЕЗ РАСПАКОВКИ: Сканируем папки в {wrk_path}")
            folders = [f for f in wrk_path.iterdir() if f.is_dir()]
            for folder in folders:
                print(f"\n[Анализ папки] {folder.name}")
                _, reps = process_bsl_directory(folder, user_values, audit_log, container_name=folder.name)
                total_replacements += reps
                processed_count += 1
        else:
            containers = list(src_path.rglob("*.epf")) + list(src_path.rglob("*.erf")) + list(src_path.rglob("*.cf"))
            print(f"\n[*] Найдено контейнеров для пайплайна: {len(containers)}")
            
            for idx, file_p in enumerate(containers, 1):
                print(f"\n[{idx}/{len(containers)}] Обработка: {file_p.name}")
                extracted_dir = wrk_path / file_p.stem
                if extracted_dir.exists():
                    shutil.rmtree(extracted_dir, ignore_errors=True)
                extracted_dir.mkdir(parents=True, exist_ok=True)
                
                success, err = run_v8unpack_saby("-u", file_p, extracted_dir)
                if not success:
                    print(f"  [!] Ошибка распаковки: {err}")
                    continue
                    
                _, reps = process_bsl_directory(extracted_dir, user_values, audit_log, container_name=file_p.name)
                total_replacements += reps
                
                out_file = tgt_path / file_p.name
                
                # Сначала упаковываем во временный файл или проверяем хэш запакованного
                temp_out = wrk_path / ("temp_" + file_p.name)
                success_pack, err_pack = run_v8unpack_saby("-p", extracted_dir, temp_out)
                
                if success_pack:
                    # Умное копирование: переносим в целевую папку только если файл изменился
                    if smart_copy_file(temp_out, out_file):
                        copied_containers += 1
                        print(f"  [OK] Запаковано и обновлено -> {out_file.name}")
                    else:
                        skipped_containers += 1
                        print(f"  [SKIP] Файл не изменился, пропущен -> {out_file.name}")
                    
                    if temp_out.exists():
                        temp_out.unlink()
                    processed_count += 1
                else:
                    print(f"  [!] Ошибка упаковки: {err_pack}")
                    
        print(f"\n[*] Пайплайн завершен. Обработано: {processed_count}. Обновлено в целевой папке: {copied_containers}, пропущено без изменений: {skipped_containers}")
    else:
        print("[!] Неверный выбор режима.")
        return

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