# === 第一阶段：构建前端 (Node.js) ===
FROM node:20-slim AS frontend-builder
WORKDIR /app-ui
# 仅拷贝 package.json 安装依赖，利用 Docker 缓存
COPY package*.json ./
# 国内服务器建议增加镜像源
RUN npm install --registry=https://registry.npmmirror.com
# 拷贝所有代码并打包
COPY . .
RUN npm run build

# === 第二阶段：构建运行环境 (Python) ===
FROM python:3.11-slim
WORKDIR /app

# 安装必要的系统工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# 拷贝后端依赖并安装
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 准备工作目录
RUN mkdir -p /app/data /app/dist

# 1. 从第一阶段拷贝生成的 dist 文件夹
COPY --from=frontend-builder /app-ui/dist /app/dist

# 2. 拷贝后端代码
COPY backend /app/backend
ENV PYTHONPATH=/app/backend

EXPOSE 8000
CMD ["python", "backend/main.py"]
