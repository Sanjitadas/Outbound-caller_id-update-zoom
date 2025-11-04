import queue
import threading
import time
import os
import logging
from logging.handlers import RotatingFileHandler

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
        task = task_queue.get()  # Wait until a task is available
        if task is None:
            logger.info("Worker thread shutting down.")
            break
        try:
            logger.info(f"[Queue Worker] Started processing task: {task['id']}")
            task['func'](*task['args'], **task['kwargs'])  # Execute task
            logger.info(f"[Queue Worker] Completed task: {task['id']}")
        except Exception as e:
            logger.error(f"[Queue Worker] Error processing task {task['id']}: {e}")
        finally:
            # Delay between tasks to prevent API rate limits
            time.sleep(0.05)  # 50 ms delay
            task_queue.task_done()

# === Start the background worker thread ===
threading.Thread(target=worker, daemon=True).start()

def add_task(task_id, func, *args, **kwargs):
    """Add a new task to the queue."""
    task = {'id': task_id, 'func': func, 'args': args, 'kwargs': kwargs}
    task_queue.put(task)
    logger.info(f"[Queue] Task {task_id} added to queue.")

