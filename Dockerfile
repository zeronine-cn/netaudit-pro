# ==========================================
# Stage 1: 前端构建阶段
# ==========================================
FROM node:20-alpine as frontend-builder

# 设置工作目录
WORKDIR /app/frontend

# 1. 单独复制依赖描述文件，利用 Docker 缓存加速依赖安装
COPY package*.json ./

# 2. 安装前端依赖
RUN npm install

# 3. 复制所有前端源代码 (注意：这会把根目录所有文件拷进去，但我们在下一步只 build)
COPY . .

# 4. 执行构建，生成 dist 目录
# 这一步会根据 vite.config.ts 将 React 代码编译成静态 HTML/JS/CSS
RUN npm run build

# ==========================================
# Stage 2: 后端运行环境 & 整合
# ==========================================
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 1. 安装系统级基础依赖 (防止某些 Python 库编译失败)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. 复制后端依赖清单
COPY backend/requirements.txt .

# 3. 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 4. 复制后端源代码
# 注意：这里我们将 backend 目录下的内容直接复制到容器的 /app 根目录
COPY backend/ .

# 5. 【关键步骤】从第一阶段复制构建好的前端静态文件
# 将 Stage 1 生成的 /app/frontend/dist 复制到当前目录下的 dist 文件夹
# 这样 main.py 里的 StaticFiles 挂载就能找到文件了
COPY --from=frontend-builder /app/frontend/dist ./dist

# 6. 创建数据持久化目录 (用于存放 sqlite 数据库)
RUN mkdir -p data

# 设置环境变量，确保 Python 日志直接输出到终端
ENV PYTHONUNBUFFERED=1

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
