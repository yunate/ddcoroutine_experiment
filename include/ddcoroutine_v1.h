#ifndef ddcoroutine_h_
#define ddcoroutine_h_

#include <coroutine>
#include <type_traits>
#include <functional>
#include <atomic>
#include <set>
#include <mutex>
#include <assert.h>

namespace dd_v1 {
template<class T>
struct ddcoroutine_value { T value{}; };
template<>
struct ddcoroutine_value<void> { };
template<class T>
struct ddcoroutine_context : public ddcoroutine_value<T>
{
    ~ddcoroutine_context()
    {
        if (self_co_handle) {
            self_co_handle.destroy();
        }
    }

    inline bool check_and_set()
    {
        return !flag.exchange(true, std::memory_order_acq_rel);
    }

    std::atomic_bool flag = false;
    std::coroutine_handle<> self_co_handle = nullptr;
    std::coroutine_handle<> caller_co_handle = nullptr;
};

template<class T>
class ddpromise_type_base
{
public:
    void return_value(T&& v)
    {
        assert(m_self_ctx != nullptr);
        m_self_ctx->value = v;
    }

    void return_value(const T& v)
    {
        assert(m_self_ctx != nullptr);
        m_self_ctx->value = v;
    }

protected:
    ddcoroutine_context<T>* m_self_ctx = nullptr;
};

template<>
class ddpromise_type_base<void>
{
public:
    void return_void() {}
protected:
    ddcoroutine_context<void>* m_self_ctx = nullptr;
};

/** 
void do_something() {}
ddcoroutine foo()
{
    do_something();
    co_return;
}

// ==>
void foo_resume(foo_co_context* co_context);
void foo_destroy(foo_co_context* co_context);
struct foo_co_context
{
    ddcoroutine::promise_type promise;
    void (*resume_fn)(foo_co_context*) = &foo_resume;
    void (*destroy_fn)(foo_co_context*) = &foo_destroy;
    int suspend_index = 0;
    std::suspend_never init_suspend;
    std::suspend_never final_suspend;
};

ddcoroutine foo()
{
    // init co context
    foo_co_context * co_context = new foo_co_context();
    auto return_obj = co_context->promise.get_return_object();

    // call foo_resume
    foo_resume(co_context);
    return return_obj;
}

void foo_resume(foo_co_context* co_context)
{
    switch(co_context->suspend_index) {
      case 0: break;
      case 1: goto resume_index_1;
      case 2: goto resume_index_2;
    }

    // co_await init_suspend
    {
        co_context->init_suspend = co_context->promise.initial_suspend();
        if(!co_context->init_suspend.await_ready()) {
          co_context->init_suspend.await_suspend(std::coroutine_handle<ddcoroutine::promise_type>::from_address(co_context->promise));
          ++co_context->suspend_index;
          return;
        }

      resume_index_1:
        co_context->init_suspend.await_resume();
    }

    do_something();

    // co_return
    co_context->promise.return_void();

    // co_await final_suspend
    {
        co_context->final_suspend = co_context->promise.final_suspend();
        if(!co_context->final_suspend.await_ready()) {
          co_context->final_suspend.await_suspend(std::coroutine_handle<ddcoroutine::promise_type>::from_address(co_context->promise));
          ++co_context->suspend_index;
          return;
        }

      resume_index_2:
        co_context->destroy_fn(co_context);
    }
}

void foo_destroy(foo_co_context* co_context)
{
  delete co_context;
}
*/
template<class T = void>
class ddcoroutine
{
public:
    const std::add_lvalue_reference_t<T> get_value()
    {
        if constexpr (!std::is_same_v<T, void>) {
            assert(m_ctx != nullptr);
            return m_ctx->value;
        }
    }

    void run()
    {
#ifdef _DEBUG
        set_and_check_called();
#endif
        assert(m_ctx != nullptr);
        m_ctx->self_co_handle.resume();
    }

public:
    auto operator co_await() const& noexcept
    {
#ifdef _DEBUG
        const_cast<ddcoroutine*>(this)->set_and_check_called();
#endif
        struct ddawaiter
        {
            constexpr bool await_ready() const noexcept { return false; }
            auto await_suspend(std::coroutine_handle<> caller_handle) noexcept
            {
                assert(m_self_ctx != nullptr);
                m_self_ctx->caller_co_handle = caller_handle;
                // why use return the co_handle rather than call co_handle.resume() [Symmetric Transfer & Tail-calls]:
                // https://lewissbaker.github.io/2020/05/11/understanding_symmetric_transfer
                // when await_suspend return std::coroutine_handle<>, it will use Tail-calls to avoid stack overflow.
                // m_self_ctx->self_co_handle.resume(); // we do not use co_handle.resume().
                return m_self_ctx->self_co_handle;
            }

            const std::add_lvalue_reference_t<T> await_resume() const noexcept
            {
                if constexpr (!std::is_same_v<T, void>) {
                    assert(m_self_ctx != nullptr);
                    return m_self_ctx->value;
                }
            }
            ddcoroutine_context<T>* m_self_ctx = nullptr;
        };
        return ddawaiter{ m_ctx.get() };
    }

    class promise_type : public ddpromise_type_base<T>
    {
    public:
        using ddpromise_type_base<T>::m_self_ctx;
        ddcoroutine<T> get_return_object()
        {
            ddcoroutine<T> tmp(std::coroutine_handle<promise_type>::from_promise(*this));
            m_self_ctx = tmp.m_ctx.get();
            return tmp;
        }

        std::suspend_always initial_suspend() noexcept { return {}; }

        auto final_suspend() noexcept
        {
            struct ddawaiter
            {
                std::coroutine_handle<> caller_handle;
                bool await_ready() const noexcept
                {
                    return false;
                }

                std::coroutine_handle<> await_suspend(std::coroutine_handle<>) noexcept
                {
                    if (caller_handle) {
                        return caller_handle;
                    } else {
                        return std::noop_coroutine();
                    }
                }

                void await_resume() const noexcept {}
            };

            return ddawaiter{ m_self_ctx->caller_co_handle };
        }
        void unhandled_exception() {}
    };

    bool operator==(const ddcoroutine& r) const { return r.m_ctx == m_ctx; }
    bool operator<(const ddcoroutine& r) const { return r.m_ctx.get() < m_ctx.get(); }
protected:
    ddcoroutine(std::coroutine_handle<> self_handle)
    {
        m_ctx = std::make_shared<ddcoroutine_context<T>>();
        m_ctx->self_co_handle = self_handle;
    }

#ifdef _DEBUG
    std::shared_ptr<std::atomic_bool> m_is_called{ new std::atomic_bool(false) };
    void set_and_check_called()
    {
        if (m_is_called->exchange(true)) {
            // run() or ddcoroutine::co_await() can be called only once.
            assert(false);
        }
    }
#endif
    std::shared_ptr<ddcoroutine_context<T>> m_ctx = nullptr;
};

struct ddcoroutine_noop
{
    struct promise_type
    {
        ddcoroutine_noop get_return_object() { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
};

// get current function's co_handle.
// e.g. std::coroutine_handle<> handle = co_await ddget_current_co_handle();
inline auto ddget_current_co_handle()
{
    struct ddawaiter
    {
        constexpr bool await_ready() const noexcept { return false; }
        constexpr std::coroutine_handle<> await_resume() const noexcept
        {
            return caller_handle;
        }
        auto await_suspend(std::coroutine_handle<> handle) noexcept
        {
            caller_handle = handle;
            return caller_handle;
        }

        std::coroutine_handle<> caller_handle;
    };

    return ddawaiter{};
}

class ddresume_helper
{
public:
    ddresume_helper(const std::function<void()>& resumer)
        : m_resumer(resumer)
    {
    }

    ~ddresume_helper()
    {
        if (m_lazy) {
            resume();
        }
    }

    inline void resume() const
    {
        if (m_resumer != nullptr) {
#ifdef _DEBUG
            check_and_set_resumed();
#endif
            m_lazy = false;
            m_resumer();
        }
    }

    // resume when destruct
    inline void lazy_resume() const
    {
        m_lazy = true;
    }

private:
#ifdef _DEBUG
    mutable std::shared_ptr<bool> m_resumed;
    void check_and_set_resumed() const
    {
        if (m_resumed == nullptr) {
            m_resumed = std::make_shared<bool>(false);
        }
        assert(!*m_resumed);
        *m_resumed = true;
    }
#endif
    mutable bool m_lazy = false;
    std::function<void()> m_resumer;
};
using ddco_task = std::function<void(const ddresume_helper& resumer)>;

// ddco_task 的回调函数必须是异步的(在另外的线程调用, 或者在同一个线程的下一次loop中调用), 否则会引发栈溢出
// 如果用这样的需求, 使用ddawaitable_ex代替
inline auto ddawaitable(const ddco_task& task)
{
    struct ddawaiter
    {
        constexpr bool await_ready() const noexcept { return false; }
        constexpr void await_resume() const noexcept {}
        void await_suspend(std::coroutine_handle<> caller_handle) noexcept
        {
            if (m_task == nullptr) {
                return;
            }

            m_task(ddresume_helper([caller_handle, this]() {
                caller_handle.resume();
            }));
        }
        ddco_task m_task = nullptr;
    };
    return ddawaiter{ task };
}

// 允许类似:
// void foo(const std::function<void()>& callback)
// {
//     callback();
// }
// 这样的, 回调函数非异步的情况.
inline auto ddawaitable_ex(const ddco_task& task)
{
    struct ddawaiter
    {
        constexpr bool await_ready() const noexcept { return false; }
        constexpr void await_resume() const noexcept {}
        bool await_suspend(std::coroutine_handle<> caller_handle) noexcept
        {
            if (m_task == nullptr) {
                return false;
            }

            m_task(ddresume_helper([caller_handle, this]() {
                if (m_flag.exchange(false, std::memory_order_acq_rel)) {
                    // path 2
                    // 有以下两种情况, 都可以认为也是同步的, 这两种情况只要让await_suspend返回false来唤醒caller即可.
                    // 1. 该callback是同步的.
                    // 2. 线程调度的非常快, await_suspend还没返回就已经完成了
                } else {
                    // path 1
                    caller_handle.resume();
                }
            }));

            if (m_flag.exchange(false, std::memory_order_acq_rel)) {
                // path 1
                // !!! 非常危险 !!!, 请注意!!!
                // 运行到这里的时候, caller_handle.resume(); 可能已经在另外的一个线程中运行了
                // 这种情况下ddawaiter已经被析构了, 在使用任何该类的成员都是未定义行为, 包括返回std::coroutine_handle<>
                // 所以本函数选择返回bool类型而不是std::coroutine_handle<>类型
                return true;
            } else {
                // path 2
                return false;
            }
        }
        ddco_task m_task = nullptr;
        std::atomic_bool m_flag = true;
    };
    return ddawaiter{ task };
};

// do not use const XXX& r, because the ref of XXX may be released
// when this coroutine resume.
// e.g.:
// ddcoroutine<void> co_async()
// {
//     co_return;
// }
// 
// ddcoroutine<void> test()
// {
//     auto x = NSP_DD::ddcoroutine_from(co_async());
//     // if use const XXX& r, the ddcoroutine which is returned by co_async() had released, ,
//     // it is an UB.
//     co_await x;
// }
inline ddcoroutine<void> ddcoroutine_from(ddco_task task)
{
    co_await ddawaitable_ex(task);
}

template<class T>
inline ddcoroutine<void> ddcoroutine_from(ddcoroutine<T> r)
{
    co_await r;
}

inline ddcoroutine<void> ddcoroutine_from(std::vector<ddcoroutine<void>> r)
{
    std::coroutine_handle<> handle = co_await ddget_current_co_handle();
    std::atomic_bool flag = true;
    std::atomic_size_t remain = r.size();
    auto wrapper_func = [&handle, &remain](const ddcoroutine<void>& co,
        std::atomic_size_t* premain,
        std::coroutine_handle<>* phandle,
        std::atomic_bool& flag) -> ddcoroutine_noop {
        co_await co;
        if (premain->fetch_sub(1) == 1) {
            if (flag.exchange(false, std::memory_order_acq_rel)) {
                // path 2
                // 1. 该callback是同步的.
                // 2. 设置m_flag线程竞争成功, 即线程调度的非常快, await_suspend还没返回就已经完成了, 这种情况可以认为也是同步的.
                // 这两种情况只要让await_suspend返回caller_handle即可.
            } else {
                // path 1
                phandle->resume();
            }
        }
        co_return;
    };

    auto wrapper_all = [&r, &remain, &handle, &wrapper_func, &flag]() {
        for (const auto& it : r) {
            wrapper_func(it, &remain, &handle, flag);
        }
    };

    struct ddawaiter
    {
        constexpr bool await_ready() const noexcept { return false; }
        constexpr void await_resume() const noexcept {}
        bool await_suspend(std::coroutine_handle<> caller_handle) const noexcept
        {
            wrapper_all();
            if (m_flag.exchange(false, std::memory_order_acq_rel)) {
                // path 1
                return true;
            } else {
                // path 2
                return false;
            }
        }
        std::function<void()> wrapper_all;
        std::atomic_bool& m_flag;
    };
    co_await ddawaiter{ wrapper_all, flag };
}

inline ddcoroutine<void> ddcoroutine_all(const std::vector<ddcoroutine<void>>& r)
{
    return ddcoroutine_from(r);
}

// 该函数允许运行一个没有返回值的ddcoroutine, 而不需要关心其生命周期;
// e.g. 一般的用法
// ddcoroutine<int> test()
// {
//     co_return 3;
// }
// int main()
// {
//     // 需要保证co不会被销毁
//     auto co = test();
//     int x = co_await co;
// }
// 
// e.g. 自动保证生命周期
// ddcoroutine<void> test()
// {
//     co_return;
// }
// int main()
// {
//     ddcoroutine_run(test());
// }
inline void ddcoroutine_run(const ddcoroutine<void>& r)
{
    class ddcoroutine_holder
    {
    public:
        inline void add_coroutine(const std::coroutine_handle<>& r)
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (m_holded_handle.find(r) == m_holded_handle.end()) {
                m_holded_handle.insert(r);
            }
        }

        inline void remove_coroutine(const std::coroutine_handle<>& r)
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (m_holded_handle.find(r) != m_holded_handle.end()) {
                m_holded_handle.erase(r);
            }
        }

        ~ddcoroutine_holder()
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            for (std::coroutine_handle<> it : m_holded_handle) {
                it.destroy();
            }
            m_holded_handle.clear();
        }
    private:
        std::set<std::coroutine_handle<>> m_holded_handle;
        std::mutex m_mutex;
    };

    static ddcoroutine_holder holder;

    auto inner_func = [](ddcoroutine<void> r) -> ddcoroutine_noop {
        std::coroutine_handle<> handle = co_await ddget_current_co_handle();
        holder.add_coroutine(handle);
        co_await r;
        holder.remove_coroutine(handle);
    };
    inner_func(r);
}
} // namespace NSP_DD
#endif // ddcoroutine_h_

