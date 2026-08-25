rule PEDosStub
{
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        $dos
}

rule QwenAiTrace
{
    strings:
        $qwen = "chat.qwen.ai" ascii
        $dash = "dashscope.aliyuncs.com" ascii
    condition:
        $qwen or $dash
}
