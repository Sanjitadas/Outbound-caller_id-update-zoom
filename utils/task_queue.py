import queue
import threading
import time
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# === Logging Setup ===
if not os.path.exists("logs"):
    os.makedirs("logs")

log_file = "logs/task_queue.log"
file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

logger = logging.getLogger("TaskQueueLogger")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

# === Thread-safe FIFO queue ===
task_queue = queue.Queue()

def worker():
    """Continuously runs and processes tasks as they arrive."""
    while True:
        task = task_queue.get()
        if task is None:
            logger.info("Worker thread shutting down.")
            break
        try:
            logger.info(f"[Queue Worker] Started task {task['id']} (User: {task['user_email']}, Action: {task['action_type']})")
            task['func'](*task['args'], **task['kwargs'])
            logger.info(f"[Queue Worker] Completed task {task['id']} (User: {task['user_email']}, Action: {task['action_type']})")
        except Exception as e:
            logger.error(f"[Queue Worker] Error in task {task['id']} by {task['user_email']}: {e}")
        finally:
            time.sleep(0.05)
            task_queue.task_done()


# === Start the background worker thread ===
threading.Thread(target=worker, daemon=True).start()

def add_task(task_id, func, *args, user_email="Unknown", action_type="General", **kwargs):
    """
    Add a new task to the queue.
    Logs user info and action type for traceability.
    """
    task = {
        'id': task_id,
        'func': func,
        'args': args,
        'kwargs': kwargs,
        'user_email': user_email,
        'action_type': action_type
    }
    task_queue.put(task)
    logger.info(f"[Queue] Task {task_id} added by {user_email} (Action: {action_type}).")

def shutdown_queue():
    """Gracefully stop the background worker."""
    task_queue.put(None)
    logger.info("[Queue] Shutdown signal sent.")

def rotate_logs_if_needed():
    now = datetime.now()
    archive_name = f"logs/archive_{now.strftime('%Y_%m')}.log"
    if not os.path.exists(archive_name):
        os.rename("logs/task_queue.log", archive_name)

def shutdown_queue():
    """Gracefully stop the worker thread when the app shuts down."""
    logger.info("[Queue] Shutting down worker thread...")
    task_queue.put(None) 