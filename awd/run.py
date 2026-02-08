from app import create_app

if __name__ == '__main__':
    print("AWD 控制台启动中...")
    print(f"请访问: http://localhost:8080")
    app = create_app()
    app.run(host='0.0.0.0', port=8080, debug=True)
