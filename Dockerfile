# === 第一阶段：使用 Python 运行环境 ===
FROM python:3.11-slim
WORKDIR /app

# 安装必要的系统工具（如 ping 等网络工具，方便审计插件使用）
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 1. 拷贝后端依赖配置并安装 Python 库
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. 准备工作目录
RUN mkdir -p /app/data /app/dist

# 3. 【关键】拷贝你在本地 Windows 打包好的前端静态文件
# 请确保你的项目根目录下有 dist 文件夹
COPY ./dist /app/dist

# 4. 拷贝后端逻辑代码
COPY backend /app/backend

# 设置环境变量，确保 Python 能够找到 backend 模块
ENV PYTHONPATH=/app/backend

# 暴露后端服务端口（容器内部端口）
EXPOSE 8000

# 启动服务 (指向 backend/main.py)
CMD ["python", "backend/main.py"]
