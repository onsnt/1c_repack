import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

# --- СИСТЕМНЫЕ КЛЮЧЕВЫЕ СЛОВА (Имена переменных слева от =) ---
SYSTEM_KEYWORDS = {
    "пароль", "password", "pwd", "secret", "token", "токен", "api_key",
    "логин", "login", "user", "пользователь", "имяпользователя",
}

EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

BLACKLIST_DIRS = {
    "Templates", "Forms", "Ext", "Tests", "Pictures", "Bin",
}

WHITELIST_FILENAMES = {
    "ObjectModule.bsl",
    "ManagerModule.bsl",
    "RecordSetModule.bsl",
    "ValueModule.bsl",
    "Module.bsl",
}

ASSIGNMENT_REGEX = re.compile(r"(?i)\b([a-zA-Zа-яА-Я0-9_]+)\s*=\s*\"([^\"]*)\"")


def content_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def load_user_values(file_path):
    """Загружает конкретные значения/логины из текстового файла."""
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


def get_safe_replacement(var_name: str, val_str: str) -> str:
    """Определяет безопасный вызов общего модуля для старых конфигураций (УПП 1.3)."""
    combined = (var_name + " " + val_str).lower()
    if any(k in combined for k in ("пароль", "password", "pwd", "secret", "token", "11")):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Пароль"
    return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Логин"


def should_skip_path(file_path, root_path) -> bool:
    try:
        rel_parts = Path(file_path).relative_to(root_path).parts
        return any(part in BLACKLIST_DIRS for part in rel_parts)
    except ValueError:
        return False


def run_v8unpack_saby(action: str, source_path, target_path, timeout: int = 60):
    """Вызов Python-пакета v8unpack (saby-integration): action = '-u' или '-p'."""
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
            timeout=timeout,
        )
        if res.returncode == 0:
            return True, ""
        return False, res.stderr.strip() or res.stdout.strip()
    except Exception as e:
        return False, str(e)


def sync_if_changed(candidate_bytes: bytes, tgt_file: Path) -> bool:
    """Записывает candidate_bytes в tgt_file, только если файл новый или его MD5 изменился."""
    if tgt_file.exists():
        try:
            if content_md5(tgt_file.read_bytes()) == content_md5(candidate_bytes):
                return False
        except Exception:
            pass

    tgt_file.parent.mkdir(parents=True, exist_ok=True)
    tgt_file.write_bytes(candidate_bytes)
    return True


def process_and_sync_file(
    src_file: Path,
    tgt_file: Path,
    user_values: set,
    audit_log: list,
    container_name: str,
    rel_path_str: str,
) -> tuple[bool, int]:
    """
    1. Берет файл из источника.
    2. Если это нужный .bsl модуль — проверяет и заменяет секреты.
    3. Если результат отличается от файла в целевом каталоге (или файла нет) — записывает в цель.
    Возвращает: (были_ли_изменения_в_целевом_файле, число_замен_секретов).
    """
    is_in_blacklist = should_skip_path(src_file, src_file.parent if not rel_path_str else src_file.anchor)
    # Проверяем по частям относительного пути
    rel_parts = Path(rel_path_str).parts
    is_in_blacklist = is_in_blacklist or any(part in BLACKLIST_DIRS for part in rel_parts)

    is_target_bsl = (
        src_file.suffix.lower() == ".bsl"
        and src_file.name in WHITELIST_FILENAMES
        and not is_in_blacklist
    )

    replacements_in_file = 0

    if is_target_bsl:
        raw_text = None
        used_encoding = "utf-8-sig"
        for enc in ("utf-8-sig", "utf-8", "cp1251"):
            try:
                raw_text = src_file.read_text(encoding=enc)
                used_encoding = enc
                break
            except UnicodeDecodeError:
                continue

        if raw_text is not None:
            def replace_match(match):
                nonlocal replacements_in_file
                var_name = match.group(1)
                var_val = match.group(2)
                val_clean = var_val.strip()

                if not val_clean or val_clean.lower() in EXCLUDED_VALUES:
                    return match.group(0)

                if var_name.lower() in SYSTEM_KEYWORDS or val_clean.lower() in user_values:
                    replacements_in_file += 1
                    safe_expr = get_safe_replacement(var_name, var_val)
                    full_match = match.group(0)
                    indent_match = re.match(r"^(\s*)", full_match)
                    indent = indent_match.group(1) if indent_match else ""
                    new_stmt = f"{indent}{var_name} = {safe_expr};"

                    audit_log.append({
                        "container": container_name,
                        "module": rel_path_str,
                        "match": full_match,
                        "replacement": new_stmt,
                    })
                    return new_stmt

                return match.group(0)

            updated_text = ASSIGNMENT_REGEX.sub(replace_match, raw_text)
            out_enc = "utf-8-sig" if used_encoding in ("utf-8-sig", "utf-8") else used_encoding
            candidate_bytes = updated_text.encode(out_enc)
        else:
            candidate_bytes = src_file.read_bytes()
    else:
        candidate_bytes = src_file.read_bytes()

    if replacements_in_file > 0:
        print(f"  [FIX] Замен в модуле ({replacements_in_file}): {rel_path_str}")

    was_written = sync_if_changed(candidate_bytes, tgt_file)
    return was_written, replacements_in_file


def process_bsl_directory_inplace(root_dir: Path, user_values: set, audit_log: list, container_name: str):
    """Сканирует и правит .bsl файлы на месте (используется для распакованных контейнеров)."""
    scanned_count = 0
    modified_count = 0
    replacements_count = 0

    for bsl_file in root_dir.rglob("*.bsl"):
        if bsl_file.name not in WHITELIST_FILENAMES:
            continue
        if should_skip_path(bsl_file, root_dir):
            continue

        scanned_count += 1
        rel_str = str(bsl_file.relative_to(root_dir))

        try:
            content = None
            used_encoding = "utf-8-sig"
            for enc in ("utf-8-sig", "utf-8", "cp1251"):
                try:
                    content = bsl_file.read_text(encoding=enc)
                    used_encoding = enc
                    break
                except UnicodeDecodeError:
                    continue

            if content is None:
                continue

            file_mutated = False
            local_replacements = 0

            def replace_match(match):
                nonlocal replacements_count, file_mutated, local_replacements
                var_name = match.group(1)
                var_val = match.group(2)
                val_clean = var_val.strip()

                if not val_clean or val_clean.lower() in EXCLUDED_VALUES:
                    return match.group(0)

                if var_name.lower() in SYSTEM_KEYWORDS or val_clean.lower() in user_values:
                    file_mutated = True
                    replacements_count += 1
                    local_replacements += 1
                    safe_expr = get_safe_replacement(var_name, var_val)
                    full_match = match.group(0)
                    indent_match = re.match(r"^(\s*)", full_match)
                    indent = indent_match.group(1) if indent_match else ""
                    new_stmt = f"{indent}{var_name} = {safe_expr};"

                    audit_log.append({
                        "container": container_name,
                        "module": rel_str,
                        "match": full_match,
                        "replacement": new_stmt,
                    })
                    return new_stmt

                return match.group(0)

            new_content = ASSIGNMENT_REGEX.sub(replace_match, content)

            if file_mutated:
                modified_count += 1
                out_enc = "utf-8-sig" if used_encoding in ("utf-8-sig", "utf-8") else used_encoding
                bsl_file.write_text(new_content, encoding=out_enc)
                print(f"  [FIX] Исправлен модуль ({local_replacements} зам.): {rel_str}")

        except Exception as ex:
            print(f"  [!] Ошибка обработки файла {bsl_file.name}: {ex}")

    print(f"[*] Проверено модулей: {scanned_count}, изменено модулей: {modified_count}, замен: {replacements_count}")
    return modified_count, replacements_count


def run_pipeline():
    print("=" * 60)
    print(" АУДИТ И РЕФАКТОРИНГ СЕКРЕТОВ В КОДЕ 1С (УПП 1.3 / EPF)")
    print("=" * 60)

    print("\nВыберите режим работы:")
    print("  1. Режим конфигурации (каталог исходников XML / EDT структуры)")
    print("  2. Режим внешних обработок / отчетов (.epf / .erf / .cf контейнеры)")

    mode = input("Введите номер режима (1 или 2): ").strip()

    src_input = input("Путь к исходному каталогу с файлами/структурой: ").strip().strip("\"'")
    tgt_input = input("Путь для сохранения результатов (готовый каталог): ").strip().strip("\"'")
    t_txt_input = input("Путь к текстовому файлу со списком логинов/учеток: ").strip().strip("\"'")

    src_path = Path(src_input).resolve()
    tgt_path = Path(tgt_input).resolve()
    user_values = load_user_values(t_txt_input)

    audit_log = []
    tgt_path.mkdir(parents=True, exist_ok=True)

    if mode == "1":
        print(f"\n[*] Режим 1: Конфигурация. Источник: {src_path} -> Цель: {tgt_path}")
        if not src_path.is_dir():
            print(f"[!] Каталог не найден: {src_path}")
            return

        synced_files = 0
        skipped_files = 0
        total_replacements = 0

        for src_file in src_path.rglob("*"):
            if not src_file.is_file():
                continue

            rel_p = src_file.relative_to(src_path)
            tgt_file = tgt_path / rel_p

            was_written, reps = process_and_sync_file(
                src_file=src_file,
                tgt_file=tgt_file,
                user_values=user_values,
                audit_log=audit_log,
                container_name="Configuration_XML",
                rel_path_str=str(rel_p),
            )
            total_replacements += reps
            if was_written:
                synced_files += 1
            else:
                skipped_files += 1

        print(
            f"\n[*] Режим 1 завершен. Записано/обновлено файлов: {synced_files}, "
            f"пропущено (без изменений): {skipped_files}, заменено секретов: {total_replacements}"
        )

    elif mode == "2":
        wrk_input = input("Путь к временной рабочей папке для распаковки: ").strip().strip("\"'")
        wrk_path = Path(wrk_input).resolve()

        skip_unpack_input = input("Пропустить этап распаковки и анализировать готовые папки? (y/N): ").strip().lower()
        skip_unpack = skip_unpack_input == "y"

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
                _, reps = process_bsl_directory_inplace(folder, user_values, audit_log, container_name=folder.name)
                total_replacements += reps
                processed_count += 1
        else:
            containers = (
                list(src_path.rglob("*.epf"))
                + list(src_path.rglob("*.erf"))
                + list(src_path.rglob("*.cf"))
            )
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

                _, reps = process_bsl_directory_inplace(extracted_dir, user_values, audit_log, container_name=file_p.name)
                total_replacements += reps

                temp_out = wrk_path / ("temp_" + file_p.name)
                out_file = tgt_path / file_p.name
                success_pack, err_pack = run_v8unpack_saby("-p", extracted_dir, temp_out)

                if success_pack and temp_out.exists():
                    if sync_if_changed(temp_out.read_bytes(), out_file):
                        copied_containers += 1
                        print(f"  [OK] Запаковано и обновлено -> {out_file.name}")
                    else:
                        skipped_containers += 1
                        print(f"  [SKIP] Контейнер не изменился, пропущен -> {out_file.name}")

                    temp_out.unlink(missing_ok=True)
                    processed_count += 1
                else:
                    print(f"  [!] Ошибка упаковки: {err_pack}")

        print(
            f"\n[*] Пайплайн завершен. Обработано: {processed_count}. "
            f"Обновлено в целевой папке: {copied_containers}, пропущено без изменений: {skipped_containers}, "
            f"заменено уязвимостей: {total_replacements}"
        )
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