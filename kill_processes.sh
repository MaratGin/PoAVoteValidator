PORT1=10098

PID=$(lsof -t -i:$PORT1)

if [ -n "$PID" ]; then
    echo "Killing process $PID on port $PORT1"
    kill -9 $PID
fi


PORT1=10037

PID2=$(lsof -t -i:$PORT)

# Если процесс найден, завершить его
if [ -n "$PID2" ]; then
    echo "Killing process $PID2 on port $PORT"
    kill -9 $PID2
fi