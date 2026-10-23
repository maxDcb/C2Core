#pragma once

#include <cstddef>
#include <string>
#include <vector>

// TCP is a byte stream. Keep the suffix of a read until its delimiter arrives.
class TcpFrameBuffer
{
public:
    static constexpr std::size_t MaxFrameBytes = 64u * 1024u * 1024u;

    bool append(const std::string& bytes, std::vector<std::string>& frames)
    {
        m_pending.append(bytes);
        const std::string& separator = delimiter();
        std::size_t start = 0;
        std::size_t end;
        while ((end = m_pending.find(separator, start)) != std::string::npos)
        {
            if (end - start > MaxFrameBytes)
            {
                reset();
                return false;
            }
            if (end != start)
                frames.emplace_back(m_pending.substr(start, end - start));
            start = end + separator.size();
        }
        m_pending.erase(0, start);
        if (m_pending.size() > MaxFrameBytes)
        {
            reset();
            return false;
        }
        return true;
    }

    void reset() { m_pending.clear(); }

    static const std::string& delimiter()
    {
        static const std::string value = "<TCP-666>";
        return value;
    }

private:
    std::string m_pending;
};
