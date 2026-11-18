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